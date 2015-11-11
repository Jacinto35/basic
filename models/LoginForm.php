<?php

namespace app\models;

class LoginForm
{
    private $user = false;
    private $model;
    private $rules = [
        [['email', 'password'], 'required'],
        ['rememberMe', 'boolean'],
    ];

    public function __construct(User $model, $post){
        $model->setEncryptionMethod('md5');
        $model->addAddValidationRules($this->rules);
        $this->model = $this->loadPostToModel($model, $post);
    }

    private function loadPostToModel($model, $post){
        if($model->load($post)){
            return $model;
        }
    }

    public function getModel(){
        return $this->model;
    }

    public function login($applicationUser){
        if ($this->model->validate()) {
            return $applicationUser->login($this->getUser(), $this->model->rememberMe ? 3600*24*30 : 0);
        }
        return false;
    }

    private function getUser(){
        if ($this->user === false) {
            $this->user = $this->model->getUser();
        }
        return $this->user;
    }
}
