export BUCKET_NAME = "cops-public"

.PHONY: requirements
requirements:
	pip install -r requirements.txt

.PHONY: cf-lint
cf-lint: requirements
	cfn-lint ./cops-ai-admin/aws/gen/*.yaml
	cfn-lint ./cops-ai-admin/aws/*.yaml

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
	  --stack-name copsai-provisioner-stack \
	  --template-body file://./cops-ai-admin/aws/copsai-provisioner-role.template.yaml \
	  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
	aws cloudformation create-stack \
	  --output text \
	  --stack-name copsai-updater-stack \
	  --template-body file://./cops-ai-admin/aws/copsai-updater-role.template.yaml \
	  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
	aws cloudformation create-stack \
	  --output text \
	  --stack-name copsai-support-stack \
	  --template-body file://./cops-ai-admin/aws/copsai-support-role.template.yaml \
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
	aws s3 cp ./cops-ai-admin/aws/gen/copsai-provisioner-role.template.yaml s3://$(BUCKET_NAME)/templates/$(RELEASE_TAG)/copsai-provisioner-role.template.yaml
	aws s3 cp ./cops-ai-admin/aws/gen/copsai-updater-role.template.yaml s3://$(BUCKET_NAME)/templates/$(RELEASE_TAG)/copsai-updater-role.template.yaml
	aws s3 cp ./cops-ai-admin/aws/gen/copsai-support-role.template.yaml s3://$(BUCKET_NAME)/templates/$(RELEASE_TAG)/copsai-support-role.template.yaml
	aws s3 cp ./cops-ai-admin/aws/cops-ai-admin-role.template.yaml s3://$(BUCKET_NAME)/templates/$(RELEASE_TAG)/cops-ai-admin-role.template.yaml