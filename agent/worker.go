package agent

import (
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/boltdb/bolt"
	"github.com/docker/swarmkit/agent/exec"
	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/log"
	"golang.org/x/net/context"
)

// Worker implements the core task management logic and persistence. It
// coordinates the set of assignments with the executor.
type Worker interface {
	// Init prepares the worker for task assignment.
	Init(ctx context.Context) error

	// AssignTasks assigns a complete set of tasks to a worker. Any task not included in
	// this set will be removed.
	AssignTasks(ctx context.Context, tasks []*api.Task) error

	// UpdateTasks updates an incremental set of tasks to the worker. Any task not included
	// either in added or removed will remain untouched.
	UpdateTasks(ctx context.Context, added []*api.Task, removed []string) error

	// Assign a complete set of secrets to a worker. Any secret not included in
	// this set will be removed.
	AssignSecrets(ctx context.Context, secrets []*api.Secret) error

	// UpdateSecrets updates an incremental set of secrets to the worker. Any secret not included
	// either in added or removed will remain untouched.
	UpdateSecrets(ctx context.Context, added []*api.Secret, removed []string) error

	// Listen to updates about tasks controlled by the worker. When first
	// called, the reporter will receive all updates for all tasks controlled
	// by the worker.
	//
	// The listener will be removed if the context is cancelled.
	Listen(ctx context.Context, reporter StatusReporter)
}

// statusReporterKey protects removal map from panic.
type statusReporterKey struct {
	StatusReporter
}

type worker struct {
	db        *bolt.DB
	executor  exec.Executor
	listeners map[*statusReporterKey]struct{}
	secrets   *Secrets

	taskManagers map[string]*taskManager
	mu           sync.RWMutex
}

func newWorker(db *bolt.DB, executor exec.Executor, secrets *Secrets) *worker {
	return &worker{
		db:           db,
		executor:     executor,
		listeners:    make(map[*statusReporterKey]struct{}),
		taskManagers: make(map[string]*taskManager),
		secrets:      secrets,
	}
}

// Init prepares the worker for assignments.
func (w *worker) Init(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	ctx = log.WithModule(ctx, "worker")

	// TODO(stevvooe): Start task cleanup process.

	// read the tasks from the database and start any task managers that may be needed.
	return w.db.Update(func(tx *bolt.Tx) error {
		return WalkTasks(tx, func(task *api.Task) error {
			if !TaskAssigned(tx, task.ID) {
				// NOTE(stevvooe): If tasks can survive worker restart, we need
				// to startup the controller and ensure they are removed. For
				// now, we can simply remove them from the database.
				if err := DeleteTask(tx, task.ID); err != nil {
					log.G(ctx).WithError(err).Errorf("error removing task %v", task.ID)
				}
				return nil
			}

			status, err := GetTaskStatus(tx, task.ID)
			if err != nil {
				log.G(ctx).WithError(err).Error("unable to read tasks status")
				return nil
			}

			task.Status = *status // merges the status into the task, ensuring we start at the right point.
			return w.startTask(ctx, tx, task)
		})
	})
}

// AssignTasks assigns  the set of tasks to the worker. Any tasks not previously known will
// be started. Any tasks that are in the task set and already running will be
// updated, if possible. Any tasks currently running on the
// worker outside the task set will be terminated.
func (w *worker) AssignTasks(ctx context.Context, tasks []*api.Task) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.G(ctx).WithFields(logrus.Fields{
		"len(tasks)": len(tasks),
	}).Debug("(*worker).AssignTasks")

	return reconcileTaskState(ctx, w, tasks, nil, true)
}

// UpdateTasks the set of tasks to the worker.
// Tasks in the added set will be added to the worker, and tasks in the removed set
// will be removed from the worker
func (w *worker) UpdateTasks(ctx context.Context, added []*api.Task, removed []string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.G(ctx).WithFields(logrus.Fields{
		"len(added)":   len(added),
		"len(removed)": len(removed),
	}).Debug("(*worker).UpdateTasks")

	return reconcileTaskState(ctx, w, added, removed, false)
}

func reconcileTaskState(ctx context.Context, w *worker, added []*api.Task, removed []string, fullSnapshot bool) error {
	tx, err := w.db.Begin(true)
	if err != nil {
		log.G(ctx).WithError(err).Error("failed starting transaction against task database")
		return err
	}
	defer tx.Rollback()

	assigned := map[string]struct{}{}

	for _, task := range added {
		log.G(ctx).WithFields(
			logrus.Fields{
				"task.id":           task.ID,
				"task.desiredstate": task.DesiredState}).Debug("assigned")
		if err := PutTask(tx, task); err != nil {
			return err
		}

		if err := SetTaskAssignment(tx, task.ID, true); err != nil {
			return err
		}

		if mgr, ok := w.taskManagers[task.ID]; ok {
			if err := mgr.Update(ctx, task); err != nil && err != ErrClosed {
				log.G(ctx).WithError(err).Error("failed updating assigned task")
			}
		} else {
			// we may have still seen the task, let's grab the status from
			// storage and replace it with our status, if we have it.
			status, err := GetTaskStatus(tx, task.ID)
			if err != nil {
				if err != errTaskUnknown {
					return err
				}

				// never seen before, register the provided status
				if err := PutTaskStatus(tx, task.ID, &task.Status); err != nil {
					return err
				}
			} else {
				task.Status = *status
			}
			w.startTask(ctx, tx, task)
		}

		assigned[task.ID] = struct{}{}
	}

	closeManager := func(tm *taskManager) {
		// when a task is no longer assigned, we shutdown the task manager for
		// it and leave cleanup to the sweeper.
		if err := tm.Close(); err != nil {
			log.G(ctx).WithError(err).Error("error closing task manager")
		}
	}

	removeTaskAssignment := func(taskID string) error {
		ctx := log.WithLogger(ctx, log.G(ctx).WithField("task.id", taskID))
		if err := SetTaskAssignment(tx, taskID, false); err != nil {
			log.G(ctx).WithError(err).Error("error setting task assignment in database")
		}
		return err
	}

	// If this was a complete set of assignments, we're going to remove all the remaining
	// tasks.
	if fullSnapshot {
		for id, tm := range w.taskManagers {
			if _, ok := assigned[id]; ok {
				continue
			}

			err := removeTaskAssignment(id)
			if err == nil {
				delete(w.taskManagers, id)
				go closeManager(tm)
			}
		}
	} else {
		// If this was an incremental set of assignments, we're going to remove only the tasks
		// in the removed set
		for _, taskID := range removed {
			err := removeTaskAssignment(taskID)
			if err != nil {
				continue
			}

			tm, ok := w.taskManagers[taskID]
			if ok {
				delete(w.taskManagers, taskID)
				go closeManager(tm)
			}
		}
	}

	return tx.Commit()
}

// AssignSecrets assigns the set of secrets to the worker. Any secrets not in this set
// will be removed.
func (w *worker) AssignSecrets(ctx context.Context, secrets []*api.Secret) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.G(ctx).WithFields(logrus.Fields{
		"len(secrets)": len(secrets),
	}).Debug("(*worker).AssignSecrets")

	return reconcileSecrets(ctx, w, secrets, nil, true)
}

// UpdateSecrets updates the set of secrets assigned to the worker.
// Serets in the added set will be added to the worker, and secrets in the removed set
// will be removed from the worker.
func (w *worker) UpdateSecrets(ctx context.Context, added []*api.Secret, removed []string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.G(ctx).WithFields(logrus.Fields{
		"len(added)":   len(added),
		"len(removed)": len(removed),
	}).Debug("(*worker).UpdateTasks")

	return reconcileSecrets(ctx, w, added, removed, false)
}

func reconcileSecrets(ctx context.Context, w *worker, added []*api.Secret, removed []string, fullSnapshot bool) error {
	// If this was a complete set of secrets, we're going to clear the secrets map and add all of them
	w.secrets.RLock()
	defer w.secrets.RUnlock()
	if fullSnapshot {
		w.secrets.m = make(map[string]*api.Secret)
		for _, secret := range added {
			w.secrets.m[secret.Name] = secret
		}
	} else {
		// If this was an incremental set of secrets, we're going to remove only the tasks
		// in the removed set
		for _, secret := range added {
			w.secrets.m[secret.Name] = secret
		}
		for _, name := range removed {
			delete(w.secrets.m, name)
		}
	}

	return nil
}

func (w *worker) Listen(ctx context.Context, reporter StatusReporter) {
	w.mu.Lock()
	defer w.mu.Unlock()

	key := &statusReporterKey{reporter}
	w.listeners[key] = struct{}{}

	go func() {
		<-ctx.Done()
		w.mu.Lock()
		defer w.mu.Unlock()
		delete(w.listeners, key) // remove the listener if the context is closed.
	}()

	// report the current statuses to the new listener
	if err := w.db.View(func(tx *bolt.Tx) error {
		return WalkTaskStatus(tx, func(id string, status *api.TaskStatus) error {
			return reporter.UpdateTaskStatus(ctx, id, status)
		})
	}); err != nil {
		log.G(ctx).WithError(err).Errorf("failed reporting initial statuses to registered listener %v", reporter)
	}
}

func (w *worker) startTask(ctx context.Context, tx *bolt.Tx, task *api.Task) error {
	_, err := w.taskManager(ctx, tx, task) // side-effect taskManager creation.

	if err != nil {
		log.G(ctx).WithError(err).Error("failed to start taskManager")
	}

	// TODO(stevvooe): Add start method for taskmanager
	return nil
}

func (w *worker) taskManager(ctx context.Context, tx *bolt.Tx, task *api.Task) (*taskManager, error) {
	if tm, ok := w.taskManagers[task.ID]; ok {
		return tm, nil
	}

	tm, err := w.newTaskManager(ctx, tx, task)
	if err != nil {
		return nil, err
	}
	w.taskManagers[task.ID] = tm
	return tm, nil
}

func (w *worker) newTaskManager(ctx context.Context, tx *bolt.Tx, task *api.Task) (*taskManager, error) {
	ctx = log.WithLogger(ctx, log.G(ctx).WithField("task.id", task.ID))

	ctlr, status, err := exec.Resolve(ctx, task, w.executor)
	if err := w.updateTaskStatus(ctx, tx, task.ID, status); err != nil {
		log.G(ctx).WithError(err).Error("error updating task status after controller resolution")
	}

	if err != nil {
		log.G(ctx).Error("controller resolution failed")
		return nil, err
	}

	return newTaskManager(ctx, task, ctlr, statusReporterFunc(func(ctx context.Context, taskID string, status *api.TaskStatus) error {
		w.mu.RLock()
		defer w.mu.RUnlock()

		return w.db.Update(func(tx *bolt.Tx) error {
			return w.updateTaskStatus(ctx, tx, taskID, status)
		})
	})), nil
}

// updateTaskStatus reports statuses to listeners, read lock must be held.
func (w *worker) updateTaskStatus(ctx context.Context, tx *bolt.Tx, taskID string, status *api.TaskStatus) error {
	if err := PutTaskStatus(tx, taskID, status); err != nil {
		log.G(ctx).WithError(err).Error("failed writing status to disk")
		return err
	}

	// broadcast the task status out.
	for key := range w.listeners {
		if err := key.StatusReporter.UpdateTaskStatus(ctx, taskID, status); err != nil {
			log.G(ctx).WithError(err).Errorf("failed updating status for reporter %v", key.StatusReporter)
		}
	}

	return nil
}
