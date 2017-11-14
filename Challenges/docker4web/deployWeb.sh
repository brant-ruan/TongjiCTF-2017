#!/bin/bash

# to deploy web challenges in docker
## for each directory
## e.g.
### ./docker4web100/
####  |
##### `-Dockerfile 
##### `-tj-web01.war

default_cnt=11001
port_cnt=$default_cnt
in_port=8080
subDirName="docker4web*"

clear

while [ 1 ]; do
	echo -e "+-----------------------------------------------------+"
	echo -e "|           CTF Web Challenges Deployment             |"
	echo -e "+-----------------------------------------------------+"
	echo -e "|           [1] Create Docker Images                  |"
	echo -e "|           [2] Run Containers Background             |"
	echo -e "|           [3] Start Containers                      |"
	echo -e "|           [4] Stop Containers                       |"
	echo -e "|           [5] Remove Containers                     |"
	echo -e "|           [6] Remove Docker Images                  |"
	echo -e "+-----------------------------------------------------+"
	echo -e "|           [7] docker image ls | grep                |"
	echo -e "|           [8] docker container ls | grep            |"
	echo -e "|           [9] docker container ls -a | grep         |"
	echo -e "+-----------------------------------------------------+"
	echo -e "|           [0] Create Some Docker Image              |"
	echo -e "|           [a] Run Some Image Background             |"
	echo -e "|           [b] Start Some Container                  |"
	echo -e "|           [c] Stop Some Container                   |"
	echo -e "|           [d] Remove Some Container                 |"
	echo -e "|           [e] Remove Some Docker Image              |"
	echo -e "|           [q] Exit                                  |"
	echo -e "+-----------------------------------------------------+"
	echo -e "$ \c"

	read opt

	if [ $opt == 'q' ]; then
		exit 0
	elif [ $opt == '1' ]; then
		for webDir in $(ls -d $subDirName); do
			cd $webDir
			docker build -t $webDir .
			cd ..
		done
		clear
	elif [ $opt == '2' ]; then
		for webDir in $(ls -d $subDirName); do
			docker run -d -p $port_cnt:$in_port $webDir
			let port_cnt=port_cnt+1
		done
	elif [ $opt == '3' ]; then
		for container in $(docker container ls -a | grep "$subDirName" | cut -d" " -f 1); do
			docker container start $container > /dev/null
			echo -e "Container [$container] is started"
		done
	elif [ $opt == '4' ]; then
		for container in $(docker container ls | grep "$subDirName" | cut -d" " -f 1); do
			docker container stop $container > /dev/null
			echo -e "Container [$container] is stopped"
		done
	elif [ $opt == '5' ]; then
		for container in $(docker container ls -a | grep "$subDirName" | cut -d" " -f 1); do
			docker container rm $container > /dev/null
			echo -e "Container [$container] is removed"
		done
	elif [ $opt == '6' ]; then
		let port_cnt=$default_cnt
		for image in $(docker image ls -a | grep "$subDirName" | cut -d" " -f 1); do
			docker image rm $image > /dev/null
			echo -e "Image [$image] is removed"
		done
	elif [ $opt == '7' ]; then
		docker image ls | grep "$subDirName"
	elif [ $opt == '8' ]; then
		docker container ls | grep "$subDirName"
	elif [ $opt == '9' ]; then
		docker container ls -a | grep "$subDirName"
	elif [ $opt == '0' ]; then
		ls -d $subDirName
		echo -e "Which to be created? (q for cancel) \c"
		read image_opt
		if [ $image_opt == 'q' ]; then
			continue
		fi
		cd $image_opt
		docker build -t $image_opt .
		cd ..
		clear
	elif [ $opt == 'a' ]; then
		docker image ls | grep "$subDirName"
		echo -e "Which to be created? (q for cancel) \c"
		read some_image
		if [ $some_image == 'q' ]; then
			continue
		fi
		echo -e "Input the port (q for cancel) \c"
		read some_port
		if [ $some_port == 'q' ]; then
			continue
		fi
		docker run -d -p $some_port:$in_port $some_image
	elif [ $opt == 'b' ]; then
		docker container ls -a | grep "$subDirName"
		echo -e "Which to be started? (use ID, q for cancel) \c"
		read start_container
		if [ $start_container == 'q' ]; then
			continue
		fi
		docker container start $start_container
	elif [ $opt == 'c' ]; then
		docker container ls | grep "$subDirName"
		echo -e "Which to be stopped? (use ID, q for cancel) \c"
		read stop_container
		if [ $stop_container == 'q' ]; then
			continue
		fi
		docker container stop $stop_container
	elif [ $opt == 'd' ]; then
		docker container ls -a | grep "$subDirName"
		echo -e "Which to be removed? (use ID, q for cancel) \c"
		read rm_container
		if [ $rm_container == 'q' ]; then
			continue
		fi
		docker container rm $rm_container
	elif [ $opt == 'e' ]; then
		docker image ls | grep "$subDirName"
		echo -e "Which to be removed? (use ID, q for cancel) \c"
		read rm_image
		if [ $rm_image == 'q' ]; then
			continue
		fi
		docker image rm $rm_image
	else
		echo -e "Invalid option"
	fi

done
