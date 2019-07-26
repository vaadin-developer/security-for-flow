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

FROM svenruppert/maven-3.6.1-openjdk:1.11.0-2
MAINTAINER sven.ruppert@gmail.com

ARG USER_HOME_DIR="/root"

#RUN curl -sL https://deb.nodesource.com/setup_12.x | bash - \
#RUN curl -sL https://deb.nodesource.com/setup_11.x | bash - \
RUN curl -sL https://deb.nodesource.com/setup_10.x | bash - \
    && apt-get install -y nodejs

WORKDIR /build
#do not delete it, it is like a reference
COPY pom.xml .
RUN mvn dependency:go-offline

ENV MAVEN_HOME /usr/share/maven
ENV MAVEN_CONFIG "$USER_HOME_DIR/.m2"

CMD ["mvn"]