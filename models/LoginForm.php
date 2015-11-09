<?php

namespace app\models;

use Yii;
use yii\base\Model;
use app\models\User;

/**
 * LoginForm is the model behind the login form.
 */
class LoginForm
{
    public $email;
    public $password;
    public $rememberMe = true;
    private $_user = false;
    private $user = false;

    public function __construct(User $user){
        $this->user = $user;

    }

    public function rules()
    {
        $formRules = [
            [['email', 'password'], 'required'],
            ['rememberMe', 'boolean'],
            ['password', 'validatePassword'],
        ];



    }


    public function validatePassword($attribute)
    {
        if (!$this->hasErrors()) {
            $user = $this->getUser();

            if (!$user || !$user->validatePassword($this->password)) {
                $this->addError($attribute, 'Incorrect login or password.');
            }
        }
    }

    public function login()
    {
        if ($this->user->validate()) {
            return Yii::$app->user->login($this->getUser(), $this->user->rememberMe ? 3600*24*30 : 0);
        }
        return false;
    }

    public function getUser()
    {
        if ($this->_user === false) {
            $this->_user = User::findByLogin($this->user->email);
        }

        return $this->_user;
    }
}
