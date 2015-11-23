# from https://gist.github.com/jhamrick/45f01c1a15572e964e5b

FROM jupyter/notebook

# Install nbgrader
RUN pip2 install nbgrader && pip3 install nbgrader

# Add any other dependencies you might want, e.g. numpy, scipy, etc.
#RUN pip2 install numpy scipy matplotlib
#RUN pip3 install numpy scipy matplotlib

# Configure grader user
RUN useradd -m grader
RUN chown -R grader:grader /home/grader
USER grader

# Where the assignments will live (these need to be mounted on runtime)
WORKDIR /assignments

ENTRYPOINT ["tini", "--", "nbgrader"]
CMD ["--help"]
