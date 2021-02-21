FROM krallin/ubuntu-tini:latest
MAINTAINER Ilya Schurov <ilya@schurov.com>

RUN apt-get -qq update 
RUN apt-get install -qq libxml2-dev libxslt1-dev python-dev
RUN apt-get install -qq gcc
RUN apt-get install -qq g++
RUN apt-get -qq -y install curl bzip2
RUN curl -sSL https://repo.continuum.io/miniconda/Miniconda3-latest-Linux-x86_64.sh -o /tmp/miniconda.sh 
RUN bash /tmp/miniconda.sh -b -f p /opt/conda
RUN rm -rf /tmp/miniconda.sh 

RUN ln -s /opt/conda/etc/profile.d/conda.sh /etc/profile.d/conda.sh

RUN echo '#!/bin/bash\n. /opt/conda/etc/profile.d/conda.sh\nconda activate base\nexec "$@"' >~/wrapper.sh
RUN chmod +x ~/wrapper.sh

RUN ~/wrapper.sh conda update conda
RUN ~/wrapper.sh conda clean --all --yes
RUN ~/wrapper.sh conda install pip

RUN ~/wrapper.sh pip install --upgrade pip
#RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN ~/wrapper.sh pip install beautifulsoup4 lxml
RUN ~/wrapper.sh conda install numpy scipy matplotlib pandas
RUN ~/wrapper.sh pip install robobrowser
RUN ~/wrapper.sh pip install amqp ipykernel ipython ipython-genutils nbconvert==5.6.1 nbformat notebook pyzmq tornado nbgrader
RUN mkdir /home/grader
RUN chown -R www-data:www-data /home/grader
RUN usermod -d /home/grader www-data


RUN echo '#!/bin/bash\n. /opt/conda/etc/profile.d/conda.sh\nconda activate base\nexec "$@"' >/home/grader/wrapper.sh
RUN chmod +x /home/grader/wrapper.sh
# Where the assignments will live (these need to be mounted on runtime)
WORKDIR /assignments
RUN chmod 777 /assignments
USER www-data
ENTRYPOINT ["/usr/local/bin/tini", "--", "/home/grader/wrapper.sh", "nbgrader"]
CMD ["--help"]

