# &#x20;1 安全配置

## &#x20;1.1 二次重打包漏洞

**1、问题描述：**

​	APP二次打包是盗版正规Android App,反编译破解后植入恶意代码，修改相关配置，重新打包。外观，功能上都和正规的App一样。但背后可能运行着恶意程序，耗电，偷流量，恶意扣费，隐私泄露等。APK的唯一识别是依靠包名和签名来判断的。

**2、检测方法**

- 使用androidkiller反编译，不做修改，然后保存。看是否可以可以安装。
- 使用apktool反编译，然后打包，签名。看是否可以正常安装

**3、修复建议**

- 在so文件中对apk、dex文件进行签名校验。
- 使用第三方软件对apk加固

## &#x20;1.2 Debug可调试漏洞

**1、问题描述**

​	在准备发布应用之前要确保关闭debug属性，即设置AndroidMainifest.xml中android:debuggable="false"，false表示关闭debug调试功能，true表示开启debug调试功能，但是有时候会忘记关掉这个属性。Debug调试开启会存在应用被调试的风险。

**2、检测方法**

解密AndroidMainfest.xml文件查看即可

**3、修复建议**

在AndroidManifest.xml文件中android:debuggable=false

## &#x20;1.3 AllowBackup数据可备份漏洞

**1、问题描述**

​	allowBackup（允许备份）是 [Android](https://www.google.com/search?q=Android&newwindow=1&sca_esv=51dcf1c7e4b6ab66&sxsrf=AE3TifO5QDWYYsf4PEXDJctx7HDtvoS_3A%3A1765288083839&ei=kyg4aaT9Mvrj2roPntWHoQI&ved=2ahUKEwi2gZf70rCRAxWXh1YBHQAiI6kQgK4QegQIARAB&uact=5&oq=AllowBackup数据可备份&gs_lp=Egxnd3Mtd2l6LXNlcnAiGkFsbG93QmFja3Vw5pWw5o2u5Y-v5aSH5Lu9MgUQABjvBTIFEAAY7wUyBRAAGO8FMggQABiABBiiBEjGC1AAWABwAHgBkAEAmAGOAaABjgGqAQMwLjG4AQPIAQD4AQL4AQGYAgGgApQBmAMAkgcDMC4xoAfgAbIHAzAuMbgHlAHCBwMyLTHIBwOACAA&sclient=gws-wiz-serp&mstk=AUtExfDRHUGKIYPQokYbAbSCzzvqiMhT17Yz98tU89tpdFgAatRv9vJB67-I2JZFNI30HIXYBZeKa3qWw5LVCOEU96JuWNzgPzFZ3CW5nB99XmyHxad-113P5RhR_hIEqBVUd1yA0FiBK8avu615a2tO9ajMzhXi4lzNiGguUQ3JRRY9fEM09Kb3TEQgB7TYjlsL3eJMVtoAPdcOfn0Pg_JLvY5J0bv42-I79nDTpXAQtNYEmrwqneU-41TPLtnbPkD960kQoOX2TPZXppHAeLLLt-Np&csui=3) 应用中一个设置，允许通过 adb backup 和adb restore 命令备份和恢复应用数据，默认值为 true，但出于安全考虑，开发者应在 AndroidManifest.xml中将其显式设为 false，以防止敏感信息（如登录凭据、聊天记录）通过未授权方式被提取，造成安全漏洞。

**2、检测方法**

​	解密AndroidMainfest.xml查看allowbackup属性是否为false。默认为true。

**3、修复建议**

​	在 AndroidManifest.xml 文件显示设置 allowBackup属性值为 false，即android:allowBackup="false"

# 2 信息泄露

## 2.1 SD卡数据明文存储

**1、问题描述**

Android系统中存放的文件存储卡有内置存储和外部存储。SDcards是外部存储，没有什么权限控制。程序只要有读写操作权限，就可以对sd卡进行读写。

**2、检测方法**

查看sdcard中相对应包名文件的数据，是否存在明文，等信息

**3、修复建议**

建议不要讲敏感信息存储在SDCard上，防止数据泄露或者被篡改，推荐存储在/data/data/packagename/目录下

## 2.2 logcat日志明文输出

**1、问题描述**

​	logcat可能会在打印中输出敏感信息，如账户信息、密码信息、手机支付号、邮箱、银行卡、token等。应用层System.out.println敏感信息输出。

​	Log.d 调试信息 输出为蓝色
​	Log.v 详细信息 输出为黑色
​	Log.i 通告信息 输出颜色为绿色
​	log.w 警告信息 输出颜色为橙色
​	Log.e 错误信息 输出为红色

**2、检测方法**

​	使用adb连接，使用logcat查看输出。

**3、修复建议**

​	使用自定义logcat类，上线前关闭logcat开关

## 2.3 敏感信息检查

**1、问题描述**

​	APP所在目录的文件权限是否设置正确，非root账户是否可以读写，执行。安卓内置了SQlite数据库，并提供增删改查等API。但却存在一些问题，如果手机root过，很容易进入到data/data/xxx/databases目录下。如果数据明文存储则会存在若干问题。

**2、检测方法**

- 对apk进行解压，查看相关文件
- 对app目录下的各个文件进行查看，关注文件权限

**3、修复建议**

- 重要数据进行加密存储
- 使用sqlcipher数据存储结合随机数，keystore等

## 2.4 Shared Preference全局可读写

**1、问题描述**



**2、检测方法**

**3、修复建议**

## 敏感信息硬编码



# 3 Activity组件漏洞

## 3.1 组件默认导出漏洞

**1、问题描述**

​	导出的Activity组件可以被第三方APP任意调用，导致敏感信息泄露，并可能受到绕过，恶意代码注入等攻击风险。Activity组件暴露相关的设置为android:exported该属性用来表示当前Activity是否可以被另一个application的组件启动。

- 当属性为true时，表示允许被启动。
- 当属性为false时表示不允许被启动，当前activity只会被当前应用或者拥有同样user ID的组件调用
- 根据Activity中intent-filter标签来判断是否可以导出。
  （1）无intent-filter,其默认属性为false。没有任何的filter意味着 只有详细描述了它的classname后才能被唤醒，就表示activity只有在内部才能使用。因为其他应用程序并不知道这个class的存在。所以在这种情况下其默认值为false。
  （2）存在filter的话，意味着这个activity可以从外部唤起，其默认值为true

- permission权限控制

  用permission来限制外部实体唤醒当前activity。android：permission指定启动该activity所需要权限名称

**2、检测方法**

**3、修复建议**

导出的Activity组件可以被第三方APP任意调用，导致敏感信息泄露，并可能受到绕过认
证、恶意代码注入等攻击风险。 Activity组件暴露
- exported属性
一、android:exported
该属性用来标示，当前Activity是否可以被另一个Application的组件启动
1. true 表示允许被启动
2. false 表示不允许被启动，这个Activity只会被当前Application或者拥有同样user ID的
Application的组件调用
3. 默认值 【1】根据Activity中是否有intent filter标签来定
- 没有intent filter - 默认值为false 没有任何的filter意味着这个Activity只有在详
细的描述了它的class name后才能被唤醒，这意味着这个Activity只能在应用内部使用，因
为其它应用程序并不知道这个class的存在，所以在这种情况下，它的默认值是false - 有
intent filter - 默认值为true
如果Activity里面至少有一个filter的话，意味着这个Activity可以被其它应用从外部唤
起，这个时候它的默认值是true
4. 权限控制
【1】不只有exported这个属性可以指定Activity是否暴露给其它应用，也可以使用
permission来限制外部实体唤醒当前Activity
【2】android:permission 指定启动该Activity所需要的权限名称

触发条件
1. 定位AndroidManifest.xml文件中的Activity组件
【1】对应的特征：<activity
2. exported属性的判断
【1】android:permission 如果设置权限控制，就认为不存在安全风险
【2】exported属性设置为true 显示设置android:exported="true" 默认值为true，也
就是具有intent filter标签，对应的特征：<intent-filter
主Activity(MainActivity) 【1】应用程序需要包含至少一个Activity组件来支持MAIN操
作和LAUNCHER种类，即为主Activity 对应的特征 【2】暴露的Activity组件不包括主
Activity

## 3.2 越权绕过漏洞

## 3.3  activity绑定browserable自定义协议

## 3.4 隐式启动intent包含敏感参数

问题描述

> 当存在两个应用具有相同的隐式启动activity需要的action时，一个应用的activity是导出的，一个应用的activity是不被导出的。那么当触发该action时，将会选择哪一个activity界面，进而能够启动那个不被导出的activity(老版本有此漏洞，4.4以上已修复)
> 在封装intent时采用隐式设置，只设定action，未限定具体的接收对象，导致intent可以被其他应用读取其中的数据

检测方法

> 查看AndroidMainfest.xml文件中的intent-filter相关

修复建议

- 将敏感信息加密
- 建议使用显式调用
- 采用权限限制Intent的范围，使用intent.setPackage,intent.setComponent,intent.setClassname,intent.setClass,new intent(context,Receivered.class)

## 

# 4 ContentProvider组件漏洞

## 4.1 组件导出漏洞

问题描述

> 内容提供器用来存放并供其他应用 访问。它们是应用程序之间共享数据的方法。provider组件导出可能会带来信息泄露风险。当Android sdk版本大于16，默认为false。

相关资料

> content URI是一个标志provider中的数据的uri。content uri中包含了整个provider的以符号表示的名字（Authority）和和指向一个表的名字（路径）。如下所示:

```
content://com.test.provider.friendship/friends
```

组成有三部分:

- content://:作为content uri的特殊标识（必须）
- 权（authority）:用于唯一标识这个content provider，外部访问者可以根据这个标识找到它，在AndroidMainfest.xml文件中配置的有。
- 路径（path）:需要访问的路径。（）暴露出的表名

检测方法

> 配置文件查看
> 检测provider组件中的export属性，再检测permission，readPermission,writePermission对应的protectionlevel,

防范措施

- 最小组件暴露。对不会参与跨应用的组件添加android:exported="false"属性。
- 设置组件访问权限。对导出的provider组件设置权限，同时将权限的protectionLevel设置为signature或者signatureOrSystem。
- 小心控制sdk版本号

其他

adb启动
adb shell content query --uri content://com.test.myprovider/job
删除：adb shell content delete --uri content://settings/settings/pointer_speed
插入：
adb shell content insert --uri content://settings/secure --bind name:s:my_number --bind value:i:24

## 组件导出漏洞

导出的Content Provider组件可以被第三方app任意调用，导致敏感信息泄露，并可能受到
目录遍历、 SQL注入等攻击风险
一、android:exported
该属性指示了content provider是否可以被其他应用程序使用
1. true
代表该content provider可以被其他应用程序使用，其他所有的应用程序都可以通过该
content provider提供的URI访问由该content provider提供的数据，在访问的时候，只需
要遵循相应的权限就行
2. false
代表该content provider对其他应用程序来说是不可见的，将android:exported设置为
false，用于限制其他应用程序来访问由该content provider提供的数据，只有当应用程序
的UID和该content provider的UID相同时，才可以访问
3. 默认值 当minSdkVersion或者targetSdkVersion小于16时该属性的默认值是true；当大
于17时，该属性默认值为false
4. 权限控制
【1】可以通过设置该属性的值为false或者通过访问权限来控制该content provider是否
可以被其他应用程序使用
【2】android:permission 指定读写该content provider数据的权限名称
二、触发条件
1. 定位AndroidManifest.xml文件中的content provider组件
【1】对应的特征：<provider
2. exported属性的判断
【1】android:permission 如果设置权限控制，就认为不存在安全风险
【2】android:exported="true" 未设置权限控制的情况下，exported属性设置为true
(默认也是true)
三、修复建议
【1】如果应用的Content Provider组件不必要导出，建议显式设置组件
的“android:exported”属性为false
【2】如果必须要有数据提供给外部应用使用，建议对组件进行权限控制



## 4.2 文件目录遍历漏洞

问题描述
Android Content Provider存在文件目录遍历安全漏洞，该漏洞源于对外暴露Content Provider组件，没有对Content Provider组件的访问进行权限控制和访问的目标文件Uri进行有效判断。攻击者利用该该应用暴露的Content provider的openFile（）接口进行文件目录遍历以达到访问任意可读文件的目的。



检测方法
查找AndroidMainfest.xml文件是否导出，进而查找openfile函数

修复建议

- 将不必要的Content Provider设置为不导出。
- 去除没有必要的openFile（）接口
- 过滤限制跨域访问，对访问的目标文件的路径进行有效判断。
- 使用Uri.decode()先对Content Query Uri进行解码后，在过滤如可通过“../”实现任意可读文件的访问Uri字符串
- 设置权限来进行内部应用通过provider 的数据共享

# 5 Service组件漏洞

## Service组件导出漏洞

导出的Service组件可以被第三方APP任意调用，导致敏感信息泄露，并可能受到权限提
升、拒绝服务等攻击风险。
一、android:exported
该属性用来标示，其他应用的组件是否可以唤醒Service或者和这个Service进行交互
1. true 表示可以
2. false
【1】表示不可以，只有同一个应用的组件或者有着同样user ID的应用可以启动这个
Service或者绑定这个Service
3. 默认值
【1】 根据当前Service是否有intent filter标签来定
- 没有intent filter - 默认值为false
没有任何的filter意味着这个Service只有在详细的描述了它的class name后才会被唤起，
这表示当前Service只能在应用内部使用，因为其它应用程序并不知道这个class的存在，所
以在这种情况下，它的默认值是false
- 有intent filter - 默认值为true 如果Service里面至少有一个filter的话，意味着该Service
可以被外部应用使用，这个时候它的默认值是true
4. 权限控制
【1】不只有exported这个属性可以指定Service是否暴露给其它应用，也可以使用
permission来限制外部实体唤醒当前Service
【2】android:permission 指定唤醒Service或与Service交互所需要的权限名称
二、触发条件
1. 定位AndroidManifest.xml文件中的Service组件
【1】对应的特征：<service
2. exported属性的判断
【1】android:permission 如果设置权限控制，就认为不存在安全风险
【2】exported属性设置为true
显示设置 android:exported="true"
默认值为true，也就是具有intent filter标签，对应的特征：<intent-filter
三、修复建议
【1】如果应用的Service组件不必要导出，或者组件配置了intent filter标签，建议显示设
置组件的“android:exported”属性为false 【2】如果组件必须要提供给外部应用使用，
建议对组件进行权限控制

## 5.1 service权限提升

问题描述：

service 是没有界面而能长时间运行在后台的应用组件。其他应用的组件可以启动一个服务运行于后台，即使用户切换到另一个应用也会继续运行。另外，一个组件可以绑定到一个service来进行交互，即使这个交互是进程间通讯也没问题。例如，一个service可能处理网络事物，播放音乐，执行文件I/O，或与一个内容提供者交互，所有这些都在后台进行。 Service不是分离开的进程，除非其他特殊情况，它不会运行在自己的进程，而是作为启动运行它的进程的一部分。Service不是线程，这意味着它将在主线程里劳作。 如果一个导出的Service没有做严格的限制，任何应用可以去启动并且绑定到这个Service上，取决于被暴露的功能，这有可能使得一个应用去执行未授权的行为，获取敏感信息或者是污染修改内部应用的状态造成威胁。

根据AndroidMainfest.xml service组件中的android:exported该属性用来表示，其他应用是否可以唤醒service或者和这个service进行交互。true表示可以，false表示不可以。

- 没有intent filter。默认值为false
  意味着这个service只有在详细的描述了class name后才会唤起。这表示service只能在应用内部使用，因为其他应用程序并不知道这个class存在。
- 有intent-filter 默认值为true
  意味着该service可以被外部应用使用
  导出的service组件可以被第三方App任意调用，导致敏感信息泄露，并可能收到权限提升，拒绝服务等攻击。

检测方法：

1. service不像broadcast receicer只能静态注册,通过反编译查看配置文件Androidmanifest.xml即可确定service,若有导出的service则进行下一步。
2. 定位AndroidManifest.xml文件中的service组件，检查exported属性是否为false。检测是否有intent-filter。是否设置权限控制。
3. 方法查看service类,重点关注onCreate/onStarCommand/onHandleIntent方法。
4. 检索所有类中startService/bindService方法及其传递的数据
5. 根据业务情况编写测试poc或者直接使用adb命令测试

其他：

启动一个服务
am startservice 服务名称
启动组件

```
am startservice -n 包名/服务名      （-n表示组件）
```

用动作启动

```
am startservice -a com.xxx.yyy.zzz(这里-a表示动作，就是在AndroidManifest.xml定义的)
```

## 5.2 Service劫持

<https://blog.csdn.net/qq_40037555/article/details/151955715>

问题描述：

启动service常用的方法是startservice（intent service），传入的参数是intent，intent使用有两种情况：

- 一个是设置action，接收到action的service，然后启动。
- 明确指定要启动的service和包名

当应用程序通过设置action来启动某个service时，恶意应用可以创建一个同样的接收action的service。在Android系统中，如果存在多个service接收同一个action的时候，首先看他们的priority值，priority值越高，就先启动哪个。如果priority值一样，就看service所属应用程序的安装顺序，启动先安装应用的service。

检测方法：

扫描应用程序的所有startservice和bindservice方法，查看启动的intent参数，判断intent是否满足以下情况：

- intent在创建时指定了class
- intent使用了setclass方法
- intent使用setComponent方法指定了package和class
  如果intent不满足以上任何一种情况，则这个service存在被外部应用劫持风险。

修复建议

> 当创建intent的时候，显示的指定要启动的Service的包名和类名，不适用action方式启动。

## 5.3 service消息伪造

问题描述
暴露的Service对外接收intent，如果构造恶意的消息放在intent中传输，被调用的service接收就可能产生安全隐患。



检测方法
查看配置文件中是否有可导出的service组件
在反编译代码中查找putextra等相关方法函数
然后查找有关url，其他信息等
修复建议
应用内部使用的service应设置为私有
内部service接收到的数据应该验证并谨慎处理
内部service需要使用签名级别的protectionLevel来判断是否内部调用
不建议在onCreate方法调用时决定是否提供服务，建议在onStartCommand，onBind，onHandleIntent等方法被调用的时候做判断。
使用显示意图只针对有明确服务需求的情况，尽量不发送敏感信息，可信任的service需要对第三方可信公司的app签名做校验

# 6 broadcast Receiver广播接收器组件漏洞

## 组件导出漏洞

导出的Broadcast Receiver组件可以被第三方APP任意调用，导致敏感信息泄露，并可能受
到权限绕过、拒绝服务等攻击风险
一、android:exported
该属性用来标示，当前Broadcast Receiver是否可以从当前应用外部获取Receiver
message
1. true 表示可以
2. false 表示不可以，当前Broadcast Receiver只能收到同一个应用或者拥有同一user ID
的Application发出的广播
3. 默认值
【1】根据当前Broadcast Receiver是否有intent filter标签来定
- 没有intent filter - 默认值为false
没有任何的filter意味着这个Receiver只有在详细的描述了它的class name后才会被唤
起，这表示当前Receiver只能在应用内部使用，因为其它应用程序并不知道这个class的存
在，所以在这种情况下，它的默认值是false
- 有intent filter - 默认值为true
如果Broadcast Receiver里面至少有一个filter的话，意味着该Receiver将会收到来自系
统或者其他应用的广播，这个时候它的默认值是true
4. 权限控制
【1】不只有exported这个属性可以指定Broadcast Receiver是否暴露给其它应用，也可
以使用permission来限制外部应用给它发送消息
【2】android:permission 指定给该Receiver发送消息所需要的权限名称
二、触发条件
1. 定位AndroidManifest.xml文件中的Broadcast Receiver组件
【1】对应的特征：<receiver
2. exported属性的判断
【1】android:permission
如果设置权限控制，就认为不存在安全风险
【2】exported属性设置为true
显示设置android:exported="true" 默认值为true，也就是具有intent filter标签，对
应的特征：<intent-filter
三、修复建议
【1】如果应用的Broadcast Receiver组件不必要导出，或者组件配置了intent filter标
签，建议显示设置组件的“android:exported”属性为false 【2】如果组件必须要接收外
部应用发送的消息，建议对组件进行权限控制

## 6.1 敏感信息泄露

问题描述
发送的intent没有明确指定接受者，而是简单的通过action进行匹配。恶意应用便可以注册一个广播接收者嗅探拦截到这个广播，如果这个广播存在敏感数据，就被恶意应用窃取了。

隐示意图发送敏感信息：

private void d(){
intent v1=new intent();
v1.setAction("com.sample.action.server_running");
v1.putExtra("xxxx",vo.h);
v1.putExtra("yyyy",v0.i);
v1.putExtra("zzzz",v0.s);
if(!TextUtils.isEmpty(v0.t))
    v1.putExtra("connected_usr",v0.t);
}
sendBroacast(v1)
POC
public void onReceive(Context context,Intent intent){
String s=null;
if(intent.getAction().equals("com.sample.action.server_running")){
String pwd=intent.getStringExtra("connected");
s="Android =>["+pwd+"]/"+intent.getExtras();
}
Toast.makeText(context.string.format("%s Received",s),Toast.LENGTH_SHORT).SHOW()
}

检测方法
对于静态注册的广播：查看配置文件中receiver,查看是否有导出，是否有intent-filter。搜索action,然后查看putextra等相关信息。
对于动态注册的广播：在反汇编代码中查找IntentFilter,registerReceiver等关键字定位所在的广播action值。然后根据找到的action,如com.xxx.yyyy等搜索，然后搜索putExtra等相关信息。
修复建议
不需要暴露的组件请设置exported="true",如果需要外部调用，建议添加自定义signature或signatureOrSystem级别的私有权限保护。
需要暴露的组件请严格检查输入参数，避免应用出现拒绝服务。
进程内动态广播注册建议使用localBroadcastManager;或者使用registerReceiver（BroadcastReceiver,Intentfilter，broadcastPermission,Handle）替代registerReceiver(registerReceiver(BroadcastReceiver,InterFilter)) 。LocalBrodcastManager.sendBroadcast()发出的广播只能被app自身广播接收器接收。

## 6.2 权限绕过漏洞

## 6.3 消息伪造漏洞

问题描述
暴露的Receiver对外接收intent，如果构造恶意的消息放在intent中传输，被调用的Receiver接收有可能产生安全隐患

检测方法
配置文件中的receiver中的可导出属性或者反汇编代码中动态注册的
查找相关参数
修复建议
使用LocalBroadcastManager.sendBroadcast()发出的广播只能被app自身广播接收器接收

LocalBroadcastManager lbm = LocalBroadcastManager.getInstance(this);
lbm.sendBroadcast(new Intent(LOCAL_ACTION));
使用LocalBroadcastManager类来进行动态注册

lbm.registerReceiver(new BroadcastReceiver() { @Override public void onReceive(Context context, Intent intent) { // TODO Handle the received local broadcast  } }, new IntentFilter(LOCAL_ACTION));
如果Receiver设置导出，则可以设置android：protectionLevel=“signature”

## 动态广播安全漏洞

**注册接收类**。该类继承BroadcastReceiver，并重写它的onReceiver（）方法。onReceiver（）就是程序接收到广播之后要进行的逻辑。

```
class TestReceiver extends BroadcastReceiver{public void onReceiver(Context content,Intent intent){  Log.d(tag,"thsi is test!")}
```

**动态注册**（默认导出）
注册方式简单明了，但缺点是必须是应用启动之后才能接收到广播，如果需要监听系统广播如开启广播，最好不要使用这种注册方式。

```
IntentFilter filter=new IntenFilter("com.example.demo1.BROADCAST");TestReceiver receiver=new TestReceiver();registerReceiver(receiver,filter);
```

首先创建爱一个IntentFilter,该对象的作用主要是说明接收的是哪一条广播。com.example.demo1.BROADCAST就是我们指明的一条广播动作，需要与广播发送时填入的动作相一致才能接收到广播。此时，广播接收者已经注册完毕。
**按钮发送**

```
Intent intent =new Intent("com.example.demo1.BROADCAST");sendBroadcast(intent);
```

这里Intent传入的参数需要与注册广播接收者IntentFilter里的参数相一致，并保证在整个应用程序中是唯一的。在发送广播时，可以在intent中传入数据，然后在OnReceive（）中获取以进行相应操作。
**动态注册的广播需要解注册**
例如在activity中注册的广播接收者，那么可以在onDestor()方法中解注册。

```
protected void onDestory(){super.onDestory();unregisterRecceiver(receiver);}
```

检测方法

- 对于静态注册的广播：查看配置文件中receiver,查看是否有导出，是否有intent-filter。搜索action,然后找到相关的发送操作
- 对于动态注册的广播：在反汇编代码中查找IntentFilter,registerReceiver等关键字定位所在的广播action值。然后根据找到的action,如com.xxx.yyyy等搜索，然后肇东相关的发送操作。

修复建议

> 使用LocalBroadcastManager类，这个类相较于Context.sendBroadcast(intent)有三方面的优势：

1. 不用担心敏感数据泄露，通过这种方式发送的广播只能应用内接收

2. 不用担心安全漏洞被利用，因为其他应用无法发送恶意广播给你

3. 比系统的全局广播更高效。

   ```
   通过命令行执行adb shell am broadcast发送广播通知。
   adb shell am broadcast 后面的参数有：
   
   [-a  <ACTION>]
   [-d <DATA_URI>]
   [-t <MIME_TYPE>] 
   [-c <CATEGORY> [-c <CATEGORY>] ...] 
   [-e|--es <EXTRA_KEY> <EXTRA_STRING_VALUE> ...] 
   [--ez <EXTRA_KEY> <EXTRA_BOOLEAN_VALUE> ...] 
   [-e|--ei <EXTRA_KEY> <EXTRA_INT_VALUE> ...] 
   [-n <COMPONENT>]
   [-f <FLAGS>] [<URI>]
   例如：
   adb shell am broadcast -a com.android.test --es test_string "this is test string" --ei test_int 100 --ez test_boolean true
   ```

   

# 7 Webview漏洞

## 7.1 密码明文存储漏洞

问题描述
Webview 默认开启密码保存功能Webview.setSavePassword(true)
开启后，在用户输入密码时，会弹出提示框；询问用户是否保存密码；
如果选择是，密码会被明文保存在/data/data/com.xxxx.yyyyy/databases/webview.db中，这样就有盗取密码的风险。

检测方法
在反编译代码中遍历查找SetSavePassword的函数路径，然后在获取函数参数值，判断参数值是否为true。
修复建议
此api在以后会启用

webSetting.setSavePassword(false)

## 7.2 addJavaScriptInterface接口安全漏洞

addJavascriptInterface可以实现本地java与js之间交互，是 Android WebView 中实现 **JavaScript 与 Java 代码交互**的重要方法。

基本用法

```java
// 创建 Java 对象供 JavaScript 调用
public class WebAppInterface {
    private Context mContext;

    public WebAppInterface(Context context) {
        mContext = context;
    }

    // 添加 @JavascriptInterface 注解，使方法可以被 JS 调用
    @JavascriptInterface
    public void showToast(String message) {
        Toast.makeText(mContext, message, Toast.LENGTH_SHORT).show();
    }

    @JavascriptInterface
    public String getDeviceInfo() {
        return "Android " + Build.VERSION.RELEASE;
    }
}

// 在 Activity/Fragment 中设置
WebView webView = findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(true);

// 添加 JavaScript 接口
webView.addJavascriptInterface(new WebAppInterface(this), "Android");
```

对应的 HTML/JavaScript 调用

```html
<!DOCTYPE html>
<html>
<body>
    <button onclick="callAndroid()">调用 Android 方法</button>
    <button onclick="getAndroidData()">获取 Android 数据</button>

    <script>
        // 调用 Android 的 showToast 方法
        function callAndroid() {
            Android.showToast("Hello from JavaScript!");
        }

        // 获取 Android 返回的数据
        function getAndroidData() {
            var info = Android.getDeviceInfo();
            alert("Device Info: " + info);
        }
        
        // Android 调用 JavaScript 方法（反向调用）
        function jsFunction(data) {
            console.log("Called from Android: " + data);
        }
    </script>
</body>
</html>
```

Android 调用 JavaScript 方法

```java
// 调用无参 JavaScript 方法
webView.loadUrl("javascript:jsFunction()");

// 调用带参 JavaScript 方法
String data = "Hello from Android";
webView.loadUrl("javascript:jsFunction('" + data + "')");

// Android 4.4+ 推荐使用 evaluateJavascript（异步，有返回值）
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    webView.evaluateJavascript("jsFunction('data')", new ValueCallback<String>() {
        @Override
        public void onReceiveValue(String value) {
            // 接收 JavaScript 返回值
            Log.d("JS", "返回值: " + value);
        }
    });
}
```



## 配置安全

- setJavaScriptEnabled(),默认为false，即不允许执行JS代码。webview.getWebSettings().setJavaScriptEnabled(true);
- setPluginState(),它有三个状态值ON,ON_DEMAND,OFF。默认为OFF.
- SetAllowFileAccess（默认为true，即允许从webview访问本地文件。
- setAllowContentAccess()默认为true，即允许从WebView加载Content URL，读取content provider相关内容.
- setAllowFileAccessFromFileURLs(),这个函数的作用是在JS没有禁用的情况下，设置是否允许file协议的URL访问其他file协议的URL的文件内容。API 15及以下默认值为true,API 16及以上默认为false。
  但是有个例外，当setAllowUniversalAccessFromFileURLs()的值为true时，setAllowFileAccessFromFileURLs()的值就不起作用了。
- setAllowUniversalAccessFromFileURLs()，这个函数的作用是在JS没有禁用的情况下，设置是否允许file协议的URL访问其他任意来源的内容。 API 15及以下默认值为true,API 16及以上默认为false.
- setSavePassword()默认值为true.这个函数的作用是设置是否允许WebView自动保存密码。





## 7.5 忽略证书错误漏洞

问题描述
WebView组件加载网页发生证书认证错误时，会WebView调用onReceivedSslError方法时，如果直接执行handler.proceed()来忽略该证书错误，则会受到中间人攻击的威胁，可能导致隐私泄露。

public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) { 
  handler.proceed(); 
} 
handler.proceed();
表示忽略证书错误，如果继续访问就有可能有中间人劫持的风险。



检测方法
静态检测自定义实现的WebViewClient类在onReceivedSslError是否调用proceed()方法

修复建议
不要重写onReceivedSslError方法，或者对于SSL证书错误问题按照业务场景判断，避免造成明文传输情况。

当发生证书认证错误时，采用默认的处理方法handler.cancel()，停止加载问题页面当发生证书认证错误时，采用默认的处理方法handler.cancel()，停止加载问题页面。

## 7.6 同源策略绕过漏洞

# 8 APP经典漏洞

## 8.1 超级拒绝服务漏洞

问题描述
	Android应用使用intent机制在组件之间传递数据，如果应用在使用getIntnet(),getAction(),Intent.getXXXXExtra()获取到空数据，异常或者畸形数据没有进行异常捕获，应用就会发生Crash，应用不可使用（本地拒绝服务）。恶意应用可以通过向受害者应用发送此类空数据，异常或者畸形数据从而使应用产生本地拒绝服务。

简单来说就是攻击者通过intent发送空数据，异常或者畸形数据导致其崩溃。本地拒绝服务漏洞不仅可以导致安全防护功能被绕过或失效（如杀毒应用，安全卫士，防盗锁屏等）。而且也可被竞争对手应用利用来攻击，使得自己的应用崩溃，造成不同程度的经济利益损失

- NullPointerException空数据异常：应用程序没有对getAction()等获取到的数据进行空指针判断，从而导致空指针异常而导致应用崩溃。

- ClassCastException类型转换异常：程序没有对getSerializableExtra()等获取到的数据进行类型判断而进行强制类型转换，从而导致类型转换异常而导致应用崩溃。
- IndexOutbound**数组越界异常：程序没有对getIntegerArrayListExtra()等获取到的数据数组元素大小的判断，从而导致数据越界访问而导致应用崩溃。
- ClassNotfoundException异常：程序没有无法找到从getSerializableExtra()获取到的序列化类对象的类定义。因此发生类未定义的异常而导致应用崩溃。

检测方法
	空intent阶段
对于此部分的检测算是初级阶段。一般只是通过AndroidManifest.xml文件获取应用导出的组件。
何为导出的组件？
在配置文件中如果应用的组件android：exported属性显式指定为true,或者并没有显式指定为true/false。但是有intent-filter并指定了相应的Action,则此组件为导出的组件。
可以使用adb命令发送空的intent给导出组件，捕获应用日志输出，查看是否有崩溃产生。

adb shell am startservice -n xxx.xxx.package/xxxx.xxx.类名
adb shell am broastcast -n
xxx.xxx.package/xxxx.xxx.类名
adb shell am start -n 
xxx.xxx.package/xxxx.xxx.类名
解析key值阶段
	空intent导致的拒绝服务只是一小部分，还有类型转换异常，数组越界异常等导致的本地拒绝服务。在解析key值阶段需要分析组件代码是否使用一些关键函数。

在Activity组件的onCreate()方法中，Service组件中的onBind()和onStartCommand()方法中，BroastcastReceiver组件的onReceive()方法中，如果组件没有做好权限控制，都可接受任意外部传过来的intent,通过查找getIntent，getAction（）和getXXExtra()这些关键函数，检测其是否有try/catch异常保护，如果没有则会有本地拒绝服务风险。

在这一阶段需要找到关键函数的key值，Action值，不仅要找到，还要找到key对应的类型来组装adb命令，发送命令给安装好的应用测试。

通用型拒绝服务阶段
15年，业界爆出了通用型拒绝服务，由于应用中使用了getSerializableExtra()的API。应用开发者没有对传入的数据作异常判断，恶意应用可以通过传入序列化数据，导致应用本地拒绝服务。此种方法传入的key值不管是否与漏洞应用相同，都会抛出类未定义的异常，相比解析key值阶段通用性大大得到了提高。
常用的手工检测poc代码如下：

```
static class SelfSerializableData implements Serializable{
private static final long serialVersionUID=42L;
public SelfSerializableData()
{super();}
....
....
构造畸形Intent
Intent intent=new Intent（）；
intent.putExtra('serializable_key',new SelfSerializableData());
针对Activity
ComponetName componentName=new ComponentName(packagename,activityname);
intent.setComponent(componentName)
startActivity(intent)
针对Service
ComponentName componentName=new ComponentName(packageName,ServiceName);
intent.setComponent(componentName);
startService(intent);
针对BroadcastReceiver
intent.setPackage(packageName)
intent.setAction(actionName)
senBroadcast(intent);
```


修复建议

- 谨慎处理接收的intent以及携带的信息
- 对于接收的任何数据进行try/catch处理，对于不符合预期的数据做异常处理，异常包括但不限于：空指针异	常，类型转换异常，数组越界访问异常，类未定义异常，序列化反序列化异常（getSerializableExtra,getParcelableExtra）

## 8.2 apk升级中间人劫持漏洞

问题描述
	apk程序存在自升级和应用提示升级两种升级方式。apk升级漏洞一般发生在第一种情况。如果没有注意开发规范，导致在下载过程中被中间人劫持。造成恶意的中间人攻击，替换目标用户实际下载的apk。
	APK进行升级时一般流程是采用请求升级接口。如果有升级，服务端返回下一个版本的下载地址，下载好后，再点击安装。过程中有三个地方可能会被劫持。

​	APP升级流程	隐患	危害
​	升级API	升级API未加密	返回恶意下载地址
​	下载API	下载API未加密	下载路径被篡改，可下载恶意APK
​	程序安装API	APK本地路径篡改	安装错误的APK
自升级危害一般是导致可以远程种马到用户手机上，并且不为用户察觉。百度浏览器曾被国外安全实验室爆出因在下载自有内核的时候可以被中间人劫持造成远程代码执行漏洞。



检测方法
查看升级接口是否使用了https
查看下载接口是否使用了https
检查安装时是否对安装包进行了安全检验

下载接口加入https。
下载接口也使用https并添加证书校验。这里着重强调的是需要对服务端返回的文件进行hash值校验或者使用RSA算法进行检验，防止文件被篡改。通过对文件hash值，还要对服务端返回的自定义key进行检验验证，防止不是自己服务器返回错误的文件。
注意下载的时候使用https返回文件下载地址以及返回文件MD5的方式，因为这时候文件下载地址和文件的MD5可以被同时中间人劫持替换，导致攻击成功

安装验证包名
安装过程也必须对apk文件进行包名和签名验证，防止apk被恶意植入代码或替换。

## 8.3 zip解压缩漏洞

问题描述

​	zip压缩包文件中存在“../”的字符串，攻击者可以通过精心构造的zip文件，利用多个“../”从而改变zip包中某个文件的存放位置，覆盖替换掉应用原有的文件。如果覆盖的是so，dex文件，odex文件，轻则产生本地拒绝服务漏洞，影响程序的可用性，重则可能造成任意代码执行漏洞，比如寄生兽漏洞，海豚浏览器远程命令执行漏洞。三星默认输入法远程代码执行等。

​	Android中现在开发过程中会有很多场景中使用到解压缩文件，比如动态加载机制，可能下载了apk/zip文件，然后在本地做解压工作，还有就是一些资源在本地占用apk包的大小，就也打包成zip放到服务端，使用的时候在下发。本地在做解压工作。那么在Android中解压zip文件，使用的是ZipInputStream和ZipEntry类。
但存在一个问题，zipEntry.getName方法返回的是zip文件中的子文件名。常规逻辑，解压到这个子文件到本地直接用相同的名字即可，但问题来了。
**zip文件中的子文件名格式没有格式要求，也就是可以包含特殊字符。但在操作系统中是有限制的，在windows和linux中是不允许的**。
但是在ZipInputStream/ZipOutputStream类却是可以的。也就是说使用ZipOutputStream类进行压缩文件，这里可以对文件名不做任何限制



检测方法

​	从功能判定是否有下载插件，字体更新，换肤，换主题等功能。
​	查看代码是否具有压缩解压缩的相关代码



## 8.4 插件动态加载漏洞



## 8.5 socket远程连接漏洞

Socket远程连接漏洞场景和危害
	Android应用通常使用PF_UNIX、PF_INET、PF_NETLINK等不同domain的socket来
进行本地IPC或者远程网络通信，这些暴露的socket代表了潜在的本地或远程攻击面，历史上也出现
过不少利用socket进行拒绝服务、root提权或者远程命令执行的案例。特别是PF_INET类型的网络
socket，可以通过网络与Android应用通信，其原本用于linux环境下开放网络服务，由于缺乏对网络
调用者身份或者本地调用者pid、permission等细粒度的安全检查机制，在实现不当的情况下，可以
突破Android的沙箱限制，以被攻击应用的权限执行命令，通常出现比较严重的漏洞。Android
安全研究的新手，可以从传统服务器渗透寻找开放socket端口的思路，去挖掘和查找此类型的漏
洞。

​	APP应用开放网络端口漏洞历史上最为典型的是虫洞漏洞，虫洞是由乌云白帽子发现的
百度系列APP存在socket远程攻击漏洞而命名的一种漏洞。漏洞的成因是如果手机开放端口，但是如果缺少对发送者的身份验证或者是存在权限控制缺陷，导致黑客拿下这个端口的权限，便可以获得手机此端口开放的所有功能。

这种漏洞可能会造成 

-  远程静默安装应用
-  远程启动任意应用
   远程打开任意网页
   远程静默添加联系人
   远程获取用用户的GPS地理位置信息/获取imei信息/安装应用信息
   远程发送任意intent广播
   远程读取写入文件等

### 1、根据端口定位app

![image-20251210225132902](C:\Users\zzw\AppData\Roaming\Typora\typora-user-images\image-20251210225132902.png)

或者使用netstatplus软件查看手机上开放的udp和tcp端口

### 2、定位APP端口漏洞的核心代码

​	得知某个应用开放某个端口以后，接下就可以在该应用的逆向代码中搜索端口号（通常是端
口号的16进制表示），重点关注ServerSocket(tcp)、DatagramSocket(udp)等类，定位到关键
代码，进一步探索潜在的攻击面

​    **TCP端口（TCP数据流）**

​	数据流形式是通过开放端口直接接收外部传来的数据进行解析，如下图所示，BufferReader传入了外界的输入数据流，然后进行readLine进行读取，对读取到的数据进行分析，顺着TCP数据读入逻辑，我们就可以对读入的数据进行分析，进一步查看是否有安全漏洞。

```Java
/**
 * 返回结果路径：当收到“stop”命令时，退出程序
 */
private static void startMonitor() {
    ServerSocket server = null;
    BufferedReader br = null;
    try {
        server = new ServerSocket();
        server.bind(new InetSocketAddress("127.0.0.1", 8888));
    } catch (Exception e) {
        System.out.println("端口绑定失败");
    }
    
    try {
        while (true) {
            Socket sock = server.accept(); // 此处会阻塞，直到收到连接
            sock.setSoTimeout(1000); // 本地通信设置较短超时时间
            br = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String readContent = br.readLine();
            System.out.println("接收到的消息是: " + readContent);
            
            // 判断接收到的信息是否为"stop"，如果是则退出程序
            if ("stop".equals(readContent)) {
                System.out.println("应用程序准备停止");
                forceExit = true; // 修改变量值，退出程序
            }
            br.close();
            sock.close();
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}
```

UDP端口

​	UDP开放端口一般使用DatagramPacket去实现数据的接收和发送，由于对系统函数不会做
混淆处理，所以首先定位到DatagramPacket之后，继续在当前类中查找receive函数，则
可以迅速定位到对接收到的数据处理的核心代码的位置。 如下图所示是创建一个
DatagramPacket进行数据接收

```Java
void doListen() {
    DatagramSocket socket = null;
    byte[] buffer = new byte[1024];
    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
    
    try {
        socket = new DatagramSocket(65502);
    } catch (Throwable t) {
        // 异常处理逻辑（原代码使用goto，这在Java中是不允许的）
        // label_1 的处理逻辑
        return;
    } catch (Exception e) {
        // label_3 的处理逻辑
        return;
    }
    
    try {
        JoinMeUpService.addListener = true;
        
        while (!JoinMeUpService.addListener) {  // 注意：这个条件可能永远为false
            a.b("HTTP", "map listener......");
            socket.receive(packet);  // 原代码中 w1.resolve(w2) 可能是 socket.receive(w3)
            
            if (!JoinMeUpService.addListener) {
                // 这里应该有处理接收到的数据的逻辑
                // 但原代码不完整
            }
        }
    } catch (Exception e) {
        // 异常处理
    }
}
```



## 8.6 ssl通信客户端信任任意证书漏洞

问题1描述：

​	在自定义实现X509TrustManager时，checkServerTrusted中没有检查证书是否可信，导致通信过程中可能存在中间人攻击，造成敏感数据劫持危害。由于客户端没有校验服务端的证书，因此攻击者就能与通讯的两端分别创建独立的联系，并交换其获得的数据，使通讯两端误认为他们正通过一个私密的连接与对方直接对话，但事实上会话已经被攻击者控制。在中间人攻击中，攻击者可以拦截通讯双方的对话并插入新的内容。

```Java
class bv implements X509TrustManager {
bv(bu parambu) {}
public void checkClientTrusted(X509Certificate[] paramArrayOfX509Certificate, String paramString)
{
// Do nothing -> accept any certificates
}
public void checkServerTrusted(X509Certificate[] paramArrayOfX509Certificate, String paramString)
{
// Do nothing -> accept any certificates
}
public X509Certificate[] getAcceptedIssuers() {
return null;
}
}
```

问题2：

在重写WebViewClient的onreceivedSSLError方法时，调用proceed忽略证书验证错误继续加载页面，导致通信过程中可能存在中间人攻击，造成敏感数据劫持

```
myWebView.setWebViewClient(new WebViewClient()
{
@Override
public void onReceivedError(WebView view, int errorCode, String description, String failingUrl)
{
// TODO Auto-generated method stub
super.onReceivedError(view, errorCode, description, failingUrl);
}
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
// TODO Auto-generated method stub
handler.proceed();
}
});
```

建议自定义实现X509TrustManager时，在checkServerTrusted中对服务器信息进行严格校验。针对自定义TrustManager，检查checkServerTrusted()函数是否为空实现。 建议不要重写TrustManager 和HostnameVerifier，使用系统默认的。 在重写WebViewClient的onReceivedSslError方法时，避免调用proceed忽略证书验证错误信息继续加载页面。 禁止使用proceed()函数忽略证书错误，应该抛给系统进行安全警告。

## 8.7 忽略域名校验

​	在自定义实现HostnameVerifier时，没有verify中进行严格证书校验，导致通信过程i中可能存在中间人攻击，造成敏感数据劫持危害。

```
HostnameVerifier hv = new HostnameVerifier() 
{ 
    @Override 
    public boolean verify(String hostname, SSLSession session) 
    { 
        // Always return true -> Accespt any host names 
        return true; 
    } 
};
```

​	在setHostnameVerifier方法中使用ALLOW_ALL_HOSTNAME_VERIFIER，信任所有Hostname，导致通信过程中可能存在中间人攻击，造成敏感数据劫持危害。

​	修补建议

  在自定义实现HostnameVerifier时，在verify中对Hostname进行严格校验。

```Java
//获得密匙库 
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultT
ype()); 
        trustStore.load(null, null); 
        SSLSocketFactory sf = new SSLSocketFactoryEx(trustStore); 
        //信任所有主机名 
        sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERI
FIER); 
        HttpParams params = new BasicHttpParams(); 
        HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1); 
        HttpProtocolParams.setContentCharset(params, HTTP.UTF_8); 
        SchemeRegistry registry = new SchemeRegistry(); 
        registry.register(new Scheme("http", PlainSocketFactory.getSock
etFactory(), 80)); 
        registry.register(new Scheme("https", sf, 443)); 
        ClientConnectionManager ccm = new ThreadSafeClientConnManager(p
arams, registry); 
        return new DefaultHttpClient(ccm, params); 
```

建议setHostnameVerifier方法中使用STRICT_HOSTNAME_VERIFIER进行严格证书校验，避免使用ALLOW_ALL_HOSTNAME_VERIFIER。
setHostnameVerifier(SSLSocketFactory.STRICT_HOSTNAME_VERIFIER);

# 9 安全权限问题

## 9.1 游离权限问题

<https://blog.csdn.net/qq_40037555/article/details/151819979>

## 9.2 冗余权限问题

<https://blog.csdn.net/weixin_39190897/article/details/124550705>

## 9.3 checkpermission以及checkselfpermission



<https://blog.csdn.net/qq_40037555/article/details/152439589?spm=1001.2014.3001.5502>

# 10 网络交互漏洞挖掘

## 10.1 http/https通信漏洞

## 10.2 验证码漏洞

## 10.3 扫一扫漏洞

## 10.4 sql注入漏洞

## 10.5 xss漏洞

## 10.6 上传漏洞

## 10.7 暴力破解

# intent安全

## pengding Intent漏洞

## intent攻击面

<https://www.ctfiot.com/270444.html>

## intent scheme URL攻击

activity 设置“android.intent.category.BROWSABLE”属性并同时设置了自定义的协议android:schme意味着可以通过浏览器打开此activity。轻则引起拒绝服务，重则演变为提权漏洞。

在AndroidManifast.xml设置schme协议之后，可能通过浏览器对app进行越权调用

app对外部过程调用和传输数据进行安全检查或查验
配置category filter, 添加android.intent.category.BROWSABLE方式规避风险

<https://blog.csdn.net/qq_35993502/article/details/121350724>

# 参考连接

[Android APP漏洞之战系列](https://github.com/WindXaa/Android-Vulnerability-Mining)

[深度解析APP四大组件漏洞挖掘](https://blog.csdn.net/Libra1313/article/details/145065918)

[App漏洞挖掘技术](https://security-kitchen.com/android/App%E6%BC%8F%E6%B4%9E%E6%8C%96%E6%8E%98%E6%8A%80%E6%9C%AF/)

[vipread移动安全](https://vipread.com/library/topic/240)

[验证码漏洞挖掘详解](https://zhuanlan.zhihu.com/p/512291808)

[android安全](https://github.com/fatboyer/Android_Security)

[intent scheme URL](https://blog.csdn.net/qq_35993502/article/details/121350724)

<https://blog.canyie.top/2024/11/05/android-platform-common-vulnerabilities/>

<https://bbs.kanxue.com/homepage-905443.htm>
