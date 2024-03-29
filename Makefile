BINARY=sds-server
GOBIN=$(GOPATH)/bin
OUT=${GOBIN}/${BINARY}
TAG=latest
HUB=sds-server

all: build test

build:
	go build -o ${OUT} main.go 
test:
	go test -v main.go
run:
	go build -o ${OUT} main.go
	./${OUT}
clean:
	go clean
	rm ${OUT}
# Please make sure that user has enough privilege to execute docker command
docker: 
	docker build -t ${HUB}/${BINARY}:${TAG} -f Dockerfile .

ctr: 
	docker build -t ${HUB}/${BINARY}:${TAG} .
	docker save -o ${BINARY}.tar ${HUB}/${BINARY}:${TAG}
	ctr -n k8s.io image import ${BINARY}.tar
	rm ${BINARY}.tar

docker-client:
	docker build -f deployment/Dockerfile .

checkENV:
ifndef HUB
  $(error Environment Variable HUB is not set)
endif
ifndef TAG
  $(error Environment Variable TAG is not set)
endif

include make/k8s_codegen.mk
