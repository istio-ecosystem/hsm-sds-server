BINDIR := _bin

export PATH := $(PWD)/$(BINDIR)/tools:$(PATH)

K8S_CODEGEN_VERSION = v0.24.2

QUOTEATTESTATION_API = https://github.com/intel/trusted-certificate-issuer.git

$(BINDIR) $(BINDIR)/scratch $(BINDIR)/tools $(BINDIR)/downloaded $(BINDIR)/downloaded/tools:
	@mkdir -p $@

$(BINDIR)/scratch/K8S_CODEGEN_VERSION: | $(BINDIR)/scratch
	@echo $(K8S_CODEGEN_VERSION) > $@

ifeq ($(shell printenv CI),)
LN := ln -f -s
else
LN := cp -f -r
endif

#####################
# k8s codegen tools #
#####################

K8S_CODEGEN_TOOLS := client-gen deepcopy-gen informer-gen lister-gen
K8S_CODEGEN_TOOLS_PATHS := $(K8S_CODEGEN_TOOLS:%=$(BINDIR)/tools/%)
K8S_CODEGEN_TOOLS_DOWNLOADS := $(K8S_CODEGEN_TOOLS:%=$(BINDIR)/downloaded/tools/%@$(K8S_CODEGEN_VERSION))

.PHONY: k8s-codegen-tools
k8s-codegen-tools: $(K8S_CODEGEN_TOOLS_PATHS)

$(K8S_CODEGEN_TOOLS_PATHS): $(BINDIR)/scratch/K8S_CODEGEN_VERSION | $(K8S_CODEGEN_TOOLS_DOWNLOADS) $(BINDIR)/tools
	cd $(dir $@) && $(LN) ../downloaded/tools/$(notdir $@)@$(K8S_CODEGEN_VERSION) $(notdir $@)

$(K8S_CODEGEN_TOOLS_DOWNLOADS): | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) go install k8s.io/code-generator/cmd/$(notdir $@)
	mv $(subst @$(K8S_CODEGEN_VERSION),,$@) $@

.PHONY: print
print:
	echo $(K8S_CODEGEN_TOOLS_DOWNLOADS)

.PHONY: clean-k8s-codegen
clean-k8s-codegen:
	rm -rf $(BINDIR)/

.PHONY: verify-codegen
verify-codegen: | k8s-codegen-tools
	VERIFY_ONLY="true" ./hack/k8s-codegen.sh \
		go \
		./$(BINDIR)/tools/client-gen \
		./$(BINDIR)/tools/deepcopy-gen \
		./$(BINDIR)/tools/informer-gen \
		./$(BINDIR)/tools/lister-gen \

.PHONY: update-codegen
update-codegen: | k8s-codegen-tools
	./hack/k8s-codegen.sh \
		go \
		./$(BINDIR)/tools/client-gen \
		./$(BINDIR)/tools/deepcopy-gen \
		./$(BINDIR)/tools/informer-gen \
		./$(BINDIR)/tools/lister-gen \

.PHONY: update-quoteattestation
update-quoteattestation:
	git clone $(QUOTEATTESTATION_API)
	mv ./trusted-certificate-issuer/api/v1alpha1/quoteattestation_types.go ./pkg/apis/tcs/v1alpha1/types_quoteattestation.go
	rm -rf ./trusted-certificate-issuer