#!/usr/bin/env bash

killall swarmd
cwd=$(PWD)
rm -rf temp
mkdir -p temp/node-1
mkdir -p temp/node-2
mkdir -p temp/node-3
mkdir -p temp/node-4

for i in 0 1 2 3 4; do
	tmux select-window -t "demo:${i}.0"
	directory="${cwd}/temp/node-${i}"
	if [[ ${i} == 0 ]]; then
		directory="${cwd}/temp"
	fi
	tmux send-keys 'C-c' 'C-c' "source ${cwd}/node-${i}/bin/activate" 'C-m'
	tmux send-keys "cd ${directory}" 'C-m' 'clear' 'C-m'
	tmux send-keys 'Enter' 'C-m'
	swarmd_cmd="swarmd -l debug --hostname node-${i} --listen-remote-api :424${i}"

	sleep 1

	case ${i} in
	0*)
	  tmux send-keys 'tree'
	  ;;
	1*)
	  tmux send-keys "${swarmd_cmd}"
	  ;;
	2*)
	  tmux send-keys "${swarmd_cmd} --join-addr :4241"
	  ;;
	3*)
	  tmux send-keys "${swarmd_cmd} --join-addr :4241 --manager"
	  ;;
	4*)
	  tmux send-keys "${swarmd_cmd} --join-addr :4241"
	  ;;
	esac
	unset swarm_cmd
done

unset cwd

tmux select-window -t "demo:0.0"
