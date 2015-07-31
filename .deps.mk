PROJ = captagent
$(PROJ)_VER = 6.0.0
$(PROJ)_TAG = 6.0.0
$(PROJ)_PACKAGE_REVISION = $(shell cd $(SRC)/$(PROJ); ../config/revision-gen $($(PROJ)_TAG))
$(PROJ)_SRPM = $(PROJ)-$($(PROJ)_VER)-$($(PROJ)_PACKAGE_REVISION).src.rpm
$(PROJ)_TAR = $(PROJ)/$(PROJ)-$($(PROJ)_VER).tar.gz

$(PROJ)_SRPM_DEFS = \
	--define "BUILD_NUMBER $($(PROJ)_PACKAGE_REVISION)" \
	--define "VERSION_NUMBER $($(PROJ)_VER)"

$(PROJ)_RPM_DEFS = \
	--define="BUILD_NUMBER $($(PROJ)_PACKAGE_REVISION)" \
	--define "VERSION_NUMBER $($(PROJ)_VER)"
