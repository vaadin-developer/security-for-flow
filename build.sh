#!/bin/bash
#
# Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

function docker_tag_exists() {
    EXISTS=$(curl -s  https://hub.docker.com/v2/repositories/$1/tags/?page_size=10000 | jq -r "[.results | .[] | .name == \"$2\"] | any")
    test $EXISTS = true
}

if docker_tag_exists working/vaadin-v14-prepared 20190628-001; then
    echo skip building, image already existing - working/vaadin-v14-prepared 20190628-001
else
    echo start building the images
    docker build -t working/vaadin-v14-prepared .
#    docker tag working/vaadin-v14-prepared:latest working/vaadin-v14-prepared:20190628-001
#    docker push working/vaadin-v14-prepared:20190628-001
fi

#svenruppert/maven-3.6.1-openjdk:1.11.0-2