<?php

namespace app\models;

/**
 * This is the model class for table "users".
 *
 * @property string $user_id
 * @property string $status
 * @property string $user_type
 * @property string $user_login
 * @property string $referer
 * @property string $is_root
 * @property string $company_id
 * @property string $last_login
 * @property string $timestamp
 * @property string $password
 * @property string $salt
 * @property string $firstname
 * @property string $lastname
 * @property string $company
 * @property string $email
 * @property string $phone
 * @property string $fax
 * @property string $url
 * @property string $tax_exempt
 * @property string $lang_code
 * @property integer $birthday
 * @property integer $purchase_timestamp_from
 * @property integer $purchase_timestamp_to
 * @property string $responsible_email
 * @property string $last_passwords
 * @property string $password_change_timestamp
 * @property string $api_key
 * @property string $janrain_identifier
 */
class User extends \yii\db\ActiveRecord implements \yii\web\IdentityInterface
{
    private $encryption;
    public $authKey;
    public $accessToken;
    public $rememberMe;
    public $rules = [
        [['company_id', 'last_login', 'timestamp', 'birthday', 'purchase_timestamp_from', 'purchase_timestamp_to', 'password_change_timestamp'], 'integer'],
        [['status', 'user_type', 'is_root', 'tax_exempt'], 'string', 'max' => 1],
        [['user_login', 'referer', 'company', 'last_passwords'], 'string', 'max' => 255],
        [['password', 'phone', 'fax', 'api_key', 'janrain_identifier'], 'string', 'max' => 32],
        [['salt'], 'string', 'max' => 10],
        [['firstname', 'lastname', 'email', 'url'], 'string', 'max' => 128],
        [['lang_code'], 'string', 'max' => 2],
        [['responsible_email'], 'string', 'max' => 80],
        ['password', 'validatePassword'],
    ];

    public static function tableName()
    {
        return 'users';
    }

    public function rules()
    {
        return $this->rules;
    }

    public function attributeLabels()
    {
        return [
            'user_id' => 'User ID',
            'status' => 'Status',
            'user_type' => 'User Type',
            'user_login' => 'User Login',
            'referer' => 'Referer',
            'is_root' => 'Is Root',
            'company_id' => 'Company ID',
            'last_login' => 'Last Login',
            'timestamp' => 'Timestamp',
            'password' => 'Password',
            'salt' => 'Salt',
            'firstname' => 'Firstname',
            'lastname' => 'Lastname',
            'company' => 'Company',
            'email' => 'Email',
            'phone' => 'Phone',
            'fax' => 'Fax',
            'url' => 'Url',
            'tax_exempt' => 'Tax Exempt',
            'lang_code' => 'Lang Code',
            'birthday' => 'Birthday',
            'purchase_timestamp_from' => 'Purchase Timestamp From',
            'purchase_timestamp_to' => 'Purchase Timestamp To',
            'responsible_email' => 'Responsible Email',
            'last_passwords' => 'Last Passwords',
            'password_change_timestamp' => 'Password Change Timestamp',
            'api_key' => 'Api Key',
            'janrain_identifier' => 'Janrain Identifier',
        ];
    }

    public static function findIdentity($id)
    {
        return self::find()
            ->where(['user_id' => $id])
            ->one();
    }

    public static function findIdentityByAccessToken($token, $type = null)
    {
        foreach (self::$users as $user) {//@TODO
            if ($user['accessToken'] === $token) {
                return new static($user);
            }
        }
        return null;
    }

    public static function findByLogin($login)
    {
        return self::find()
            ->where(['email' => $login])
            ->one();
    }

    public function getId()
    {
        return $this->user_id;
    }

    public function getAuthKey()
    {
        return $this->authKey;
    }

    public function validateAuthKey($authKey)
    {
        return $this->authKey === $authKey;
    }

    public function validatePassword($attribute)
    {
        if (!$this->hasErrors()) {
            $user = $this->getUser();
            if (!$user || !$user->validateUserPassword($this->password, $this->encryption)) {
                $this->addError($attribute, 'Incorrect login or password.');
            }
        }
    }

    public function getUser(){
        return self::findByLogin($this->email);
    }

    public function validateUserPassword($password, $encryption)
    {
        if($encryption && in_array($encryption, array('md5','sha1'))){
            return $this->password === $encryption($password);
        }
        return $this->password === $password;
    }

    public function setEncryptionMethod($encryption){
        $this->encryption = $encryption;
    }

    public function addAddValidationRules($rules)
    {
        $this->rules = array_merge($this->rules, $rules);
    }


}
