#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

PLATFORM := $(shell uname)
MAKEFLAGS += PLATFORM=$(PLATFORM)

ifndef LIBCRYPTO_ROOT
	export LIBCRYPTO_ROOT = $(shell echo "`pwd`/libcrypto-root")
endif

export S2N_ROOT=$(shell pwd)
export COVERAGE_DIR = $(shell echo "${S2N_ROOT}/coverage")
DIRS=$(wildcard */)
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

.PHONY : all
all: bin
	$(MAKE) -C tests

bitcode :
	${MAKE} -C tests/saw bitcode

.PHONY : bc
bc:
	${MAKE} -C crypto bc
	${MAKE} -C stuffer bc
	${MAKE} -C tls bc
	${MAKE} -C utils bc
.PHONY : saw
saw : bc
	$(MAKE) -C tests/saw

include s2n.mk

.PHONY : libs
libs:
	$(MAKE) -C utils
	$(MAKE) -C error
	$(MAKE) -C stuffer
	$(MAKE) -C crypto
	$(MAKE) -C tls
	$(MAKE) -C lib

.PHONY : bin
bin: libs
	$(MAKE) -C bin

.PHONY : integrationv2
integrationv2: bin
	$(MAKE) -C tests integrationv2

.PHONY : coverage
coverage: run-lcov run-genhtml

.PHONY : run-lcov
run-lcov:
	$(MAKE) -C bin lcov
	$(MAKE) -C crypto lcov
	$(MAKE) -C error lcov
	$(MAKE) -C stuffer lcov
	$(MAKE) -C tests lcov
	$(MAKE) -C tls run-lcov
	$(MAKE) -C utils lcov
	lcov -a crypto/coverage.info -a error/coverage.info -a stuffer/coverage.info -a tls/coverage.info -a $(wildcard tls/*/coverage.info) -a utils/coverage.info --output ${COVERAGE_DIR}/all_coverage.info

.PHONY : run-genhtml
run-genhtml:
	genhtml -o ${COVERAGE_DIR}/html ${COVERAGE_DIR}/all_coverage.info


.PHONY : indent
indent:
	$(MAKE) -C tests indentsource
	$(MAKE) -C stuffer indentsource
	$(MAKE) -C crypto indentsource
	$(MAKE) -C utils indentsource
	$(MAKE) -C error indentsource
	$(MAKE) -C tls indent
	$(MAKE) -C bin indentsource

.PHONY : pre_commit_check
pre_commit_check: all indent clean

# TODO use awslabs instead
DEV_IMAGE ?= camshaft/s2n-dev
DEV_OPENSSL_VERSION ?= openssl-1.1.1
DEV_VERSION ?= ubuntu_18.04_$(DEV_OPENSSL_VERSION)_gcc9

dev:
	@docker run -it --rm --ulimit memlock=-1 -v `pwd`:/home/s2n-dev/s2n $(DEV_IMAGE):$(DEV_VERSION)

.PHONY : install
install: bin libs
	$(MAKE) -C bin install
	$(MAKE) -C lib install

.PHONY: uninstall
uninstall:
	$(MAKE) -C bin uninstall
	$(MAKE) -C lib uninstall

.PHONY : clean
clean:
	$(MAKE) -C tests clean
	$(MAKE) -C stuffer decruft
	$(MAKE) -C crypto decruft
	$(MAKE) -C utils decruft
	$(MAKE) -C error decruft
	$(MAKE) -C tls clean
	$(MAKE) -C bin decruft
	$(MAKE) -C lib decruft
	$(MAKE) -C coverage clean
