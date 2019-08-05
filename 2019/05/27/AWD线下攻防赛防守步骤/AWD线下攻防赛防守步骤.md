---
title: AWD线下攻防赛防守步骤
date: 2019-05-27 16:14:39
tags:
---
**目录 (Table of Contents)**

[TOCM]

[TOC]

# 0x00 引言
**由于本人是个菜鸡，对web掌握也不是很好，在比赛中也只能做做简单的防御工作。参加过几次比赛，运气比较好，也都取得了差不多的名次。下面分享一下AWD线下赛的防守方法。**

# 0x01 改密码
####1. 登录密码
　　登录密码就是ssh的密码，比赛时会给登录到防守服务器的用户名和密码。一般来说每个队伍的密码都是随机生成的，不改也可以，不过改了之后能方便队友连接服务器和后期操作。如果每个队伍的密码都是相同的会给大家5分钟左右的准备时间，用来改密码和其他准备工作。

####2. Web后台密码
　　web后台弱口令几乎是每次比赛必考的，因此这是一个比拼手速的过程。首先，从网站的配置文件中找到数据库的用户名和密码（也可以直接在后台尝试弱口令爆破），这里推荐一个比较快速的查找数据库用户名和密码的方式。

![1](https://raw.githubusercontent.com/LiuTianzheng/LiuTianzheng.github.io/master/png/1.png)

　　利用notepad++的文件查找功能，选中目标文件夹，搜索3306。

![2](https://raw.githubusercontent.com/LiuTianzheng/LiuTianzheng.github.io/master/png/2.png)

　　然后利用账号密码登录数据库，查找后台用户名和密码。
```bash
root@ubuntu$ mysql -u username -ppassword
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 4
Server version: 5.7.18 MySQL Community Server (GPL)

Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| phpcms             |
+--------------------+
2 rows in set (0.00 sec)

mysql> use phpcms;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------------+
| Tables_in_phpcms      |
+-----------------------+
| v9_admin              |
| v9_admin_panel        |
| v9_admin_role         |
| v9_admin_role_priv    |
| v9_announce           |
| v9_attachment         |
| v9_attachment_index   |
| v9_badword            |
| v9_block              |
| v9_block_history      |
| v9_block_priv         |
| v9_cache              |
| v9_category           |
| v9_category_priv      |
| v9_collection_content |
| v9_collection_history |
| v9_collection_node    |
| v9_collection_program |
| v9_comment            |
| v9_comment_check      |
| v9_comment_data_1     |
| v9_comment_setting    |
| v9_comment_table      |
| v9_content_check      |
| v9_copyfrom           |
| v9_datacall           |
| v9_dbsource           |
| v9_download           |
| v9_download_data      |
| v9_downservers        |
| v9_extend_setting     |
| v9_favorite           |
| v9_hits               |
| v9_ipbanned           |
| v9_keylink            |
| v9_keyword            |
| v9_keyword_data       |
| v9_link               |
| v9_linkage            |
| v9_log                |
| v9_member             |
| v9_member_detail      |
| v9_member_group       |
| v9_member_menu        |
| v9_member_verify      |
| v9_member_vip         |
| v9_menu               |
| v9_message            |
| v9_message_data       |
| v9_message_group      |
| v9_model              |
| v9_model_field        |
| v9_module             |
| v9_mood               |
| v9_news               |
| v9_news_data          |
| v9_page               |
| v9_pay_account        |
| v9_pay_payment        |
| v9_pay_spend          |
| v9_picture            |
| v9_picture_data       |
| v9_position           |
| v9_position_data      |
| v9_poster             |
| v9_poster_201705      |
| v9_poster_space       |
| v9_queue              |
| v9_release_point      |
| v9_search             |
| v9_search_keyword     |
| v9_session            |
| v9_site               |
| v9_sms_report         |
| v9_special            |
| v9_special_c_data     |
| v9_special_content    |
| v9_sphinx_counter     |
| v9_sso_admin          |
| v9_sso_applications   |
| v9_sso_members        |
| v9_sso_messagequeue   |
| v9_sso_session        |
| v9_sso_settings       |
| v9_tag                |
| v9_template_bak       |
| v9_times              |
| v9_type               |
| v9_urlrule            |
| v9_video              |
| v9_video_content      |
| v9_video_data         |
| v9_video_store        |
| v9_vote_data          |
| v9_vote_option        |
| v9_vote_subject       |
| v9_wap                |
| v9_wap_type           |
| v9_workflow           |
+-----------------------+
99 rows in set (0.00 sec)

mysql> select * from v9_admin;
+--------+----------+----------------------------------+--------+---------+-------------+---------------+--------------+----------+------+------+
| userid | username | password                         | roleid | encrypt | lastloginip | lastlogintime | email        | realname | card | lang |
+--------+----------+----------------------------------+--------+---------+-------------+---------------+--------------+----------+------+------+
|      1 | admin    | 27ae133841a9a903b0ba33dd2731c19f |      1 | HvdsJS  | 192.168.2.4 |    1494213467 | admin@qq.com |          |      |      |
+--------+----------+----------------------------------+--------+---------+-------------+---------------+--------------+----------+------+------+
1 row in set (0.00 sec)

mysql>

```
　　查找到用户名和密码之后，可以通过update命令来修改对应字段。
```bash
mysql> update table_name set password = 'string' where username = 'admin';
```

　　也可以将加密的密码解密，然后登录后台进行修改。

# 0x02 下载源码
####1. 使用Xftp、MobaXterm等软件或者远程桌面
　　用Xftp或MobaXterm建立远程文件连接

####2. 找到源码位置打包并下载
　　查找源码位置，首先查看中间件。
```bash
root@ubuntu$ netstat -tunlp | grep 80
tcp     0    0 0.0.0.0:80     0.0.0.0:*    LISTEN    894/nginx: master p
```
    各个中间件源码默认路径：
    Apache：/var/www/html
    Nginx：/usr/share/nginx/html
    Tomcat：/var/lib/tomcatX/webapps

　　找到源码位置后，将源码打包，可以提高下载源码速度。

```bash
#打包命令
root@ubuntu$ tar cvf src_1.tar ./html
#解包命令
root@ubuntu$ tar xvf src_1.tar
```
# 0x03 用D盾扫描源码
　　将下载完的源码拖到D盾中进行扫描
![3](https://raw.githubusercontent.com/LiuTianzheng/LiuTianzheng.github.io/master/png/3.png)
# 0x04 删除后门
　　将扫描到的后门在服务器源码中删除或者注释掉。
# 0x05 改源码目录权限
　　我们可以修改源码目录的权限，使其他队伍不能获得足够的权限来获取flag。
```bash
root@ubuntu$ chmod 755 /var/www/html/….
root@ubuntu$ chmod 766 /var/www/html/…./uploadfiles
```
# 0x06 上传waf或者监控脚本
　　为了过滤掉其他队伍的敏感输入请求，我们可以给关键的php文件挂上waf，这样即使他们找到了漏洞也不容易打进来。
```php
<?php
error_reporting(0);
//ini_set('display_errors', 1);
/*
** 线下攻防php版本waf
**
*/

class waf{

	private $request_url;
	private $request_method;
	private $request_data;
	private $headers;
	private $raw;
	/*
	waf类
	*/


// 自动部署构造方法
function __construct(){
	//echo "class waf construct execute..</br>";   //debug code
	$this->write_access_log_probably();  //记录访问纪录    类似于日志
	$this->write_access_logs_detailed();  //纪录详细访问请求包  
	//echo "class waf construct execute..2</br>";
	if($_SERVER['REQUEST_METHOD'] != 'POST' && $_SERVER['REQUEST_METHOD'] != 'GET'){
    write_attack_log("method");
	}
	//echo "class waf construct execute..3</br>";
	$this->request_url= $_SERVER['REQUEST_URI']; //获取url来进行检测


	$this->request_data = file_get_contents('php://input'); //获取post

	$this->headers =$this->get_all_headers(); //获取header  

	//echo "class waf construct execute half..</br>";


	$this->filter_attack_keyword($this->filter_invisible(urldecode($this->filter_0x25($this->request_url)))); //对URL进行检测，出现问题则拦截并记录
	$this->filter_attack_keyword($this->filter_invisible(urldecode($this->filter_0x25($this->request_data)))); //对POST的内容进行检测，出现问题拦截并记录
	//echo "class waf construct execute..4</br>";
	$this->detect_upload();

	$this->gloabel_attack_detect();


	//echo "class waf construct execute  success..</br>";



}

//全局输入检测  基本的url和post检测过了则对所有输入进行简单过滤

function gloabel_attack_detect(){

	foreach ($_GET as $key => $value) {
		$_GET[$key] = $this->filter_dangerous_words($value);
	}
	foreach ($_POST as $key => $value) {
		$_POST[$key] = $this->filter_dangerous_words($value);
	}
	foreach ($headers as $key => $value) {
		$this->filter_attack_keyword($this->filter_invisible(urldecode(filter_0x25($value)))); //对http请求头进行检测，出现问题拦截并记录
		$_SERVER[$key] = $this->filter_dangerous_words($value); //简单过滤
	}
}


//拦截所有的文件上传  并记录上传操作  并将上传文件保存至系统tmp文件夹下
function detect_upload(){
	foreach ($_FILES as $key => $value) {
        if($_FILES[$key]['size']>1){
			echo "upload file error";
			$this->write_attack_log("Upload");
			//move_uploaded_file($_FILES[$key]["tmp_name"],'/tmp/uoloadfiles/'.$_FILES[$key]["name"]);
			exit(0);
		}
    }
}


//记录每次大概访问记录，类似日志，以便在详细记录中查找
function write_access_log_probably() {
    $raw = date("Y/m/d H:i:s").'    ';
    $raw .= $_SERVER['REQUEST_METHOD'].'     '.$_SERVER['REQUEST_URI'].'     '.$_SERVER['REMOTE_ADDR'].'    ';
    $raw .= 'POST: '.file_get_contents('php://input')."\r\n";
	$ffff = fopen('all_requests.txt', 'a'); //日志路径
    fwrite($ffff, $raw);  
    fclose($ffff);
}

//记录详细的访问头记录，包括GET POST http头   以获取通防waf未检测到的攻击payload
function write_access_logs_detailed(){
    $data = date("Y/m/d H:i:s")." -- "."\r\n".$this->get_http_raws()."\r\n\r\n";
    $ffff = fopen('all_requests_detail.txt', 'a'); //日志路径
    fwrite($ffff, urldecode($data));  
    fclose($ffff);
}

/*
获取http请求头并写入数组
*/
function get_all_headers() {
    $headers = array();

    foreach($_SERVER as $key => $value) {
        if(substr($key, 0, 5) === 'HTTP_') {
            $headers[$key] = $value;
        }
    }

    return $headers;
}
/*
检测不可见字符造成的截断和绕过效果，注意网站请求带中文需要简单修改
*/
function filter_invisible($str){
    for($i=0;$i<strlen($str);$i++){
        $ascii = ord($str[$i]);
        if($ascii>126 || $ascii < 32){ //有中文这里要修改
            if(!in_array($ascii, array(9,10,13))){
                write_attack_log("interrupt");
            }else{
                $str = str_replace($ascii, " ", $str);
            }
        }
    }
    $str = str_replace(array("`","|",";",","), " ", $str);
    return $str;
}

/*
检测网站程序存在二次编码绕过漏洞造成的%25绕过，此处是循环将%25替换成%，直至不存在%25
*/
function filter_0x25($str){
    if(strpos($str,"%25") !== false){
        $str = str_replace("%25", "%", $str);
        return filter_0x25($str);
    }else{
        return $str;
    }
} 	


/*
攻击关键字检测，此处由于之前将特殊字符替换成空格，即使存在绕过特性也绕不过正则的\b
*/
function filter_attack_keyword($str){
    if(preg_match("/select\b|insert\b|update\b|drop\b|and\b|delete\b|dumpfile\b|outfile\b|load_file|rename\b|floor\(|extractvalue|updatexml|name_const|multipoint\(/i", $str)){
        $this->write_attack_log("sqli");
    }

    //文件包含的检测
    if(substr_count($str,$_SERVER['PHP_SELF']) < 2){
        $tmp = str_replace($_SERVER['PHP_SELF'], "", $str);
        if(preg_match("/\.\.|.*\.php[35]{0,1}/i", $tmp)){
            $this->write_attack_log("LFI/LFR");;
        }
    }else{
        $this->write_attack_log("LFI/LFR");
    }
    if(preg_match("/base64_decode|eval\(|assert\(|file_put_contents|fwrite|curl|system|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restorei/i", $str)){
        $this->write_attack_log("EXEC");
    }
    if(preg_match("/flag/i", $str)){
        $this->write_attack_log("GETFLAG");
    }

}

/*
简单将易出现问题的字符替换成中文
*/
function filter_dangerous_words($str){
    $str = str_replace("'", "‘", $str);
    $str = str_replace("\"", "“", $str);
    $str = str_replace("<", "《", $str);
    $str = str_replace(">", "》", $str);
    return $str;
}

/*
获取http的请求包，意义在于获取别人的攻击payload
*/
function get_http_raws() {
    $raw = '';

    $raw .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\r\n";

    foreach($_SERVER as $key => $value) {
        if(substr($key, 0, 5) === 'HTTP_') {
            $key = substr($key, 5);
            $key = str_replace('_', '-', $key);
            $raw .= $key.': '.$value."\r\n";
        }
    }
    $raw .= "\r\n";
    $raw .= file_get_contents('php://input');
    return $raw;
}

/*
这里拦截并记录攻击payload      第一个参数为记录类型   第二个参数是日志内容   使用时直接调用函数
*/
function write_attack_log($alert){
    $data = date("Y/m/d H:i:s")." -- [".$alert."]"."\r\n".$this->get_http_raws()."\r\n\r\n";
    $ffff = fopen('attack_detected_log.txt', 'a'); //日志路径
    fwrite($ffff, $data);  
    fclose($ffff);
    if($alert == 'GETFLAG'){
        echo "CTF{H4Ck_IS_s0_c001}"; //如果请求带有flag关键字，显示假的flag。（2333333）
    }else{
        sleep(3); //拦截前延时3秒
    }
    exit(0);
}


}
$waf = new waf();

?>

```
　　但是挂通防waf有一个问题，就是可能会被checkdown。如果被checkdown我们可以挂一个简单的流量监控waf，监控所有打过来的数据包，获取payload来攻击其他队伍。
```php
<?php

error_reporting(0);
define('LOG_FILEDIR','./logs');
function waf()
{
if (!function_exists('getallheaders')) {
function getallheaders() {
foreach ($_SERVER as $name => $value) {
if (substr($name, 0, 5) == 'HTTP_')
$headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
}
return $headers;
}
}
$get = $_GET;
$post = $_POST;
$cookie = $_COOKIE;
$header = getallheaders();
$files = $_FILES;
$ip = $_SERVER["REMOTE_ADDR"];
$method = $_SERVER['REQUEST_METHOD'];
$filepath = $_SERVER["SCRIPT_NAME"];
foreach ($_FILES as $key => $value) {
$files[$key]['content'] = file_get_contents($_FILES[$key]['tmp_name']);
file_put_contents($_FILES[$key]['tmp_name'], "virink");
}

unset($header['Accept']);
$input = array("Get"=>$get, "Post"=>$post, "Cookie"=>$cookie, "File"=>$files, "Header"=>$header);

logging($input);

}

function logging($var){
$filename = $_SERVER['REMOTE_ADDR'];
$LOG_FILENAME = LOG_FILEDIR."/".$filename;
$time = date("Y-m-d G:i:s");
file_put_contents($LOG_FILENAME, "\r\n".$time."\r\n".print_r($var, true), FILE_APPEND);
file_put_contents($LOG_FILENAME,"\r\n".'http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'].'?'.$_SERVER['QUERY_STRING'], FILE_APPEND);
file_put_contents($LOG_FILENAME,"\r\n***************************************************************",FILE_APPEND);
}

waf();
?>
```
# 0x07 时刻关注流量和积分榜
　　时刻看着自己的分数，看到自己被down了就赶紧恢复，不管被删库还是被自己删了什么重要配置文件或者还是上的通用waf脚本过不了check，然后就是查看流量了。
# 0x08 布置文件监控
　　我们还可以在关键文件夹布置文件监控，将上传上来的任何文件都删掉。
```python
# -*- coding: utf-8 -*-
#use: python file_check.py ./

import os
import hashlib
import shutil
import ntpath
import time

CWD = os.getcwd()
FILE_MD5_DICT = {}      # 文件MD5字典
ORIGIN_FILE_LIST = []

# 特殊文件路径字符串
Special_path_str = 'drops_JWI96TY7ZKNMQPDRUOSG0FLH41A3C5EXVB82'
bakstring = 'bak_EAR1IBM0JT9HZ75WU4Y3Q8KLPCX26NDFOGVS'
logstring = 'log_WMY4RVTLAJFB28960SC3KZX7EUP1IHOQN5GD'
webshellstring = 'webshell_WMY4RVTLAJFB28960SC3KZX7EUP1IHOQN5GD'
difffile = 'diff_UMTGPJO17F82K35Z0LEDA6QB9WH4IYRXVSCN'

Special_string = 'drops_log'  # 免死金牌
UNICODE_ENCODING = "utf-8"
INVALID_UNICODE_CHAR_FORMAT = r"\?%02x"

# 文件路径字典
spec_base_path = os.path.realpath(os.path.join(CWD, Special_path_str))
Special_path = {
    'bak' : os.path.realpath(os.path.join(spec_base_path, bakstring)),
    'log' : os.path.realpath(os.path.join(spec_base_path, logstring)),
    'webshell' : os.path.realpath(os.path.join(spec_base_path, webshellstring)),
    'difffile' : os.path.realpath(os.path.join(spec_base_path, difffile)),
}

def isListLike(value):
    return isinstance(value, (list, tuple, set))

# 获取Unicode编码
def getUnicode(value, encoding=None, noneToNull=False):

    if noneToNull and value is None:
        return NULL

    if isListLike(value):
        value = list(getUnicode(_, encoding, noneToNull) for _ in value)
        return value

    if isinstance(value, unicode):
        return value
    elif isinstance(value, basestring):
        while True:
            try:
                return unicode(value, encoding or UNICODE_ENCODING)
            except UnicodeDecodeError, ex:
                try:
                    return unicode(value, UNICODE_ENCODING)
                except:
                    value = value[:ex.start] + "".join(INVALID_UNICODE_CHAR_FORMAT % ord(_) for _ in value[ex.start:ex.end]) + value[ex.end:]
    else:
        try:
            return unicode(value)
        except UnicodeDecodeError:
            return unicode(str(value), errors="ignore")

# 目录创建
def mkdir_p(path):
    import errno
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

# 获取当前所有文件路径
def getfilelist(cwd):
    filelist = []
    for root,subdirs, files in os.walk(cwd):
        for filepath in files:
            originalfile = os.path.join(root, filepath)
            if Special_path_str not in originalfile:
                filelist.append(originalfile)
    return filelist

# 计算机文件MD5值
def calcMD5(filepath):
    try:
        with open(filepath,'rb') as f:
            md5obj = hashlib.md5()
            md5obj.update(f.read())
            hash = md5obj.hexdigest()
            return hash
    except Exception, e:
        print u'[!] getmd5_error : ' + getUnicode(filepath)
        print getUnicode(e)
        try:
            ORIGIN_FILE_LIST.remove(filepath)
            FILE_MD5_DICT.pop(filepath, None)
        except KeyError, e:
            pass

# 获取所有文件MD5
def getfilemd5dict(filelist = []):
    filemd5dict = {}
    for ori_file in filelist:
        if Special_path_str not in ori_file:
            md5 = calcMD5(os.path.realpath(ori_file))
            if md5:
                filemd5dict[ori_file] = md5
    return filemd5dict

# 备份所有文件
def backup_file(filelist=[]):
    # if len(os.listdir(Special_path['bak'])) == 0:
    for filepath in filelist:
        if Special_path_str not in filepath:
            shutil.copy2(filepath, Special_path['bak'])

if __name__ == '__main__':
    print u'---------start------------'
    for value in Special_path:
        mkdir_p(Special_path[value])
    # 获取所有文件路径，并获取所有文件的MD5，同时备份所有文件
    ORIGIN_FILE_LIST = getfilelist(CWD)
    FILE_MD5_DICT = getfilemd5dict(ORIGIN_FILE_LIST)
    backup_file(ORIGIN_FILE_LIST) # TODO 备份文件可能会产生重名BUG
    print u'[*] pre work end!'
    while True:
        file_list = getfilelist(CWD)
        # 移除新上传文件
        diff_file_list = list(set(file_list) ^ set(ORIGIN_FILE_LIST))
        if len(diff_file_list) != 0:
            # import pdb;pdb.set_trace()
            for filepath in diff_file_list:
                try:
                    f = open(filepath, 'r').read()
                except Exception, e:
                    break
                if Special_string not in f:
                    try:
                        print u'[*] webshell find : ' + getUnicode(filepath)
                        shutil.move(filepath, os.path.join(Special_path['webshell'], ntpath.basename(filepath) + '.txt'))
                    except Exception as e:
                        print u'[!] move webshell error, "%s" maybe is webshell.'%getUnicode(filepath)
                    try:
                        f = open(os.path.join(Special_path['log'], 'log.txt'), 'a')
                        f.write('newfile: ' + getUnicode(filepath) + ' : ' + str(time.ctime()) + '\n')
                        f.close()
                    except Exception as e:
                        print u'[-] log error : file move error: ' + getUnicode(e)

        # 防止任意文件被修改,还原被修改文件
        md5_dict = getfilemd5dict(ORIGIN_FILE_LIST)
        for filekey in md5_dict:
            if md5_dict[filekey] != FILE_MD5_DICT[filekey]:
                try:
                    f = open(filekey, 'r').read()
                except Exception, e:
                    break
                if Special_string not in f:
                    try:
                        print u'[*] file had be change : ' + getUnicode(filekey)
                        shutil.move(filekey, os.path.join(Special_path['difffile'], ntpath.basename(filekey) + '.txt'))
                        shutil.move(os.path.join(Special_path['bak'], ntpath.basename(filekey)), filekey)
                    except Exception as e:
                        print u'[!] move webshell error, "%s" maybe is webshell.'%getUnicode(filekey)
                    try:
                        f = open(os.path.join(Special_path['log'], 'log.txt'), 'a')
                        f.write('diff_file: ' + getUnicode(filekey) + ' : ' + getUnicode(time.ctime()) + '\n')
                        f.close()
                    except Exception as e:
                        print u'[-] log error : done_diff: ' + getUnicode(filekey)
                        pass
        time.sleep(2)
        # print '[*] ' + getUnicode(time.ctime())
```
用法：将文件拷入web目录，chmod提权：chmod 777 ./SimpleMonitor_64，执行脚本：./SimpleMonitor_64。

# 0x09 查看日志
查找日志文件备份并删除日志中内容

#### 1、Apache日志
	①通过apache配置文件，找到日志存放地址：
```bash
  root@ubuntu$ find / -name "httpd.conf"
```

	②找到配置文件地址，在里边找到apache的access_log与error_log存放地址

      Error_log "/private/var/log/apache2/error_log"
      Access_log "/private/var/log/apache2/access_log"

	③可以将日志文件下载下来用日志查看器查看，也可以直接使用命令查看
```bash
  root@ubuntu$ tail -f /private/var/log/apache2/access_log
```

#### 2、Nginx日志

	①通过nginx配置文件，找到日志存放地址：
```bash
  root@ubuntu$ find / -name nginx.conf
```


	②根据找到的地址，进入nginx.conf文件进行查找路径
```bash
  root@ubuntu$ vi /usr/share/nginx/conf/nginx.conf
```
      /var/logdata/nginx/access.log
      /var/logdata/nginx/error.log

	③查看日志
```bash
  root@ubuntu$ tail -f /var/logdata/nginx/access.log
```

#### 3、Tomcat日志

	 ①查找Tomcat日志文件
      Tomcate的日志包含:
		  catalina.log，host-manager.log，localhost.log，manager.log
		用find命令查找

	②查看日志
		tail -f catalina.out
