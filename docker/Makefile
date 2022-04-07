version=0.1
img_name=rares
ctr_name=rares-river

build:
	docker image build -t ${img_name}:${version} --build-arg VERSION=${version} .

test: build
	docker run --rm --name ${ctr_name} ${img_name}:${version}

run: build
	docker run -it --name ${ctr_name} \
		--mount type=bind,source="$(shell pwd)"/../,target=/home/circleci/rares/ \
		--cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
		${img_name}:${version} /bin/bash

rm-ctr:
	docker container rm -f ${ctr_name}

bash:
	docker exec -it ${ctr_name} /bin/bash

clean:
	docker rm -f ${ctr_name}
	docker image rm ${img_name}:${version}
