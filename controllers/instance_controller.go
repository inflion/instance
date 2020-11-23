/*
Copyright 2020 inflion.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "k8s.io/api/core/v1"

	inflionv1beta1 "github.com/inflion/instance/api/v1beta1"
)

// InstanceReconciler reconciles a Instance object
type InstanceReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=inflion.inflion.com,resources=instances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=inflion.inflion.com,resources=instances/status,verbs=get;update;patch

func (r *InstanceReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("instance", req.NamespacedName)

	var instance inflionv1beta1.Instance

	if err := r.Get(ctx, req.NamespacedName, &instance); err != nil {
		log.Error(err, "unable to get instance")
		return ctrl.Result{}, err
	}

	// get aws secret via r.Get
	var sec v1.Secret
	err := r.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: "aws-access-secrets"}, &sec)
	if err != nil {
		log.Error(err, "unable to get secret")
		return ctrl.Result{}, err
	}
	err = os.Setenv("AWS_ACCESS_KEY_ID", string(sec.Data["aws_access_key"]))
	if err != nil {
		log.Error(err, "unable to set os env")
		return ctrl.Result{}, err
	}
	err = os.Setenv("AWS_SECRET_ACCESS_KEY", string(sec.Data["aws_access_secret"]))
	if err != nil {
		log.Error(err, "unable to set os env")
		return ctrl.Result{}, err
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		log.Error(err, "unable to create aws session")
		return ctrl.Result{}, err
	}

	conf := aws.Config{Region: aws.String("ap-northeast-1")}
	api := Api{conn: ec2.New(sess, &conf)}

	i, err := api.GetInstanceById(instance.Spec.InstanceId)
	if err != nil {
		log.Error(err, "unable to get instance")
		return ctrl.Result{}, err
	}
	ic := NewInstanceWithConnection(i, api.conn)

	// Sleep instance
	if i.Status == "running" && instance.Status.Sleeping == true {
		log.Info("sleep instance")
		ic.Stop()
	}

	// Wake instance up
	if i.Status == "stopped" && instance.Status.Sleeping == false {
		log.Info("wake instance up")
		ic.Start()
	}

	return ctrl.Result{}, nil
}

func (r *InstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&inflionv1beta1.Instance{}).
		Complete(r)
}
