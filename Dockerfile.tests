##
# Used to test Salus is operating correctly in the docker container itself.
##
# docker build -t salus-local .
# docker build -f Dockerfile.tests -t salus-tests .
# docker run salus-tests

FROM salus-local

COPY spec /home/spec

RUN bundle install --with test

ENTRYPOINT ["bundle", "exec", "rspec", "--format", "documentation", "spec/"]
