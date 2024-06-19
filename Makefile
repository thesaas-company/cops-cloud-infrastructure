export BUCKET_NAME = "cops-public"

.PHONY: requirements
requirements:
	pip install -r requirements.txt

.PHONY: cf-lint
cf-lint: requirements
	cfn-lint ./gen/*.yaml

.PHONY: generate
generate:
	python scripts/generate.py

.PHONY: lint
lint: requirements
	black --check scripts/generate.py

.PHONY: create-stack
create-stack: requirements lint generate cf-lint
	aws cloudformation create-stack \
	  --output text \
	  --stack-name cops-provisioner-stack \
	  --template-body file://./gen/cops-provisioner-role.template.yaml \
	  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
	aws cloudformation create-stack \
	  --output text \
	  --stack-name cops-updater-stack \
	  --template-body file://./gen/cops-updater-role.template.yaml \
	  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
	aws cloudformation create-stack \
	  --output text \
	  --stack-name cops-support-stack \
	  --template-body file://./gen/cops-support-role.template.yaml \
	  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND

# RELEASE_TAG=v5.1.1 make release_cloudformation
.PHONY: release_cloudformation
release_cloudformation:
	# Create Git Release
	git tag $(RELEASE_TAG)
	git push origin $(RELEASE_TAG)

	# Create directory for the new release
	aws s3api put-object --bucket $(BUCKET_NAME) --key templates/$(RELEASE_TAG)/
	# Upload the CloudFormation template to the new release directory
	aws s3 cp ./gen/cops-provisioner-role.template.yaml s3://$(BUCKET_NAME)/templates/$(RELEASE_TAG)/cops-provisioner-role.template.yaml
	aws s3 cp ./gen/cops-updater-role.template.yaml s3://$(BUCKET_NAME)/templates/$(RELEASE_TAG)/cops-updater-role.template.yaml
	aws s3 cp ./gen/cops-support-role.template.yaml s3://$(BUCKET_NAME)/templates/$(RELEASE_TAG)/cops-support-role.template.yaml
	aws s3 cp ./gen/cops-karpenter-role.template.yaml s3://$(BUCKET_NAME)/templates/$(RELEASE_TAG)/cops-karpenter-role.template.yaml