ARG PROCESSOR_IMAGE
FROM ${PROCESSOR_IMAGE}

USER 0:0
RUN mv /usr/local/bin/faultlane /usr/local/bin/faultlane-real
COPY --chmod=0755 deploy/processor/proof-wrapper /usr/local/bin/faultlane
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/faultlane"]
