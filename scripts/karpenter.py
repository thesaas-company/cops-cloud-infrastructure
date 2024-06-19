from troposphere import (
    Template, Ref, Sub, GetAtt, Join
)
from troposphere.iam import Role, Policy, ManagedPolicy
from troposphere.sqs import Queue, QueuePolicy
from troposphere.events import Rule





print(t.to_yaml())
