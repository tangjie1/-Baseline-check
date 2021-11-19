<#
# Author: tangjie
# Add_time: 2020/12/28
# V2.0_time：2021/03/26
# Windows安全配置策略基线检测脚本
#>
#$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
#@{} 创建一个哈希表
#@() 创建一个数组
$data = @{"project"=@()}
secedit /export /cfg config.cfg /quiet
Write-Host "=================================="
Write-Host "|  Windows baseline check-HANSON |"
Write-Host "|         version:2.0            |"
Write-Host "|         welcome!               |"
Write-Host "=================================="
Write-Host "=================================="
Write-Host ".................................."
Write-Host "脚本说明:                        ."
Write-Host "# TRUE 检查配置无问题！          ."
Write-Host "# FAIL 检查配置有问题！          ."
Write-Host "# MANUAL 需要手工检查确认！      ."
Write-Host ".................................."

#需求：
#扫描结束后，输出扫描结果。
#扫描总条目数、正确条目数、错误条目数、需要手工检查条目数。

#设置变量
#初始化总条目变量
$all = 0
#初始化正确条目变量
$t = 0
#初始化错误条目变量
$f = 0
#初始化需要手工检查变量
$m = 0


$ip = (ipconfig|select-string "IPV4"|out-string).split(":")[1].split("I")[0].Trim(" ").Trim(".-`t`n`r")
$houzhui = ".csv"
$file_name = $ip + $houzhui
echo "$file_name"
#生成csv格式，分列以“tab键”为分隔符！
echo "章节	检查项	级别	调整要求	检查项说明	标准值	检查情况	符合性	调整情况	原因" >>  $file_name
#帐号口令

#3.1 检查是否已正确配置密码最长使用期限策略
$all = $all +1
$MaximumPasswordAge = Get-content -path config.cfg | findstr MaximumPasswordAge
if($MaximumPasswordAge -ne $null){
	$config = Get-Content -path config.cfg

	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "MaximumPasswordAge "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			$test = $config_line[1]
			if($config_line[1] -le "90")
			{
				#$data.code = "1"
				$projectdata = @{"true"="3.1 检查是否已正确配置密码最长使用期限策略 <=90 $test TRUE";}
				echo "3.1	检查是否已正确配置密码最长使用期限策略	可选	建议调整	长期不修改密码辉增加密码暴露风险，除入域服务器或服务器超管账号已分段无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	$test	TRUE		" >> $file_name
				$data['project']+=$projectdata

			}
			else
			{
				#$data.code = "0"
				$projectdata = @{"fail"="3.1 检查是否已正确配置密码最长使用期限策略 FAIL";}
				echo "3.1	检查是否已正确配置密码最长使用期限策略	可选	建议调整	长期不修改密码辉增加密码暴露风险，除入域服务器或服务器超管账号已分段无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	$test	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}
	}
}

else{
	$projectdata = @{"manual"="3.1 检查是否已正确配置密码最长使用期限策略 >=8  MANUAL";}
	echo "3.1	检查是否已正确配置密码最长使用期限策略	可选	建议调整	长期不修改密码辉增加密码暴露风险，除入域服务器或服务器超管账号已分段无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	null	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}
#3.2 检查是否已配置密码长度最小值
$all = $all +1
$MinimumPasswordLength = Get-content -path config.cfg | findstr MinimumPasswordLength
if($MinimumPasswordLength -ne $null){

	$config = Get-Content -path config.cfg
	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "MinimumPasswordLength "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			$test32 = $config_line[1]
			if($config_line[1] -ge "8")
			{
				#$data.code = "1"
				$projectdata = @{"true"="3.2 检查是否已配置密码长度最小值 >=8 $test32 TRUE";}
				echo "3.2	检查是否已配置密码长度最小值	可选	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，密码长度最小值为8位。此检查项建议调整	>=8	$test32	TRUE		" >> $file_name
				$data['project']+=$projectdata
			}
			else
			{
				#$data.code = "0"
				$projectdata = @{"fail"="3.2 检查是否已配置密码长度最小值 >=8 $test32 FAIL";}
				echo "3.2	检查是否已配置密码长度最小值	可选	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，密码长度最小值为8位。此检查项建议调整	>=8	$test32	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}
	}
}
else{
	$projectdata = @{"manual"="3.2 检查是否已配置密码长度最小值 >=8 $test32 MANUAL";}
	echo "3.2	检查是否已配置密码长度最小值	可选	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，密码长度最小值为8位。此检查项建议调整	>=8	null	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}
#3.3 检查是否已正确配置“强制密码历史"
$all = $all +1
$PasswordHistorySize = Get-content -path config.cfg | findstr PasswordHistorySize
if($PasswordHistorySize -ne $null){



	$config = Get-Content -path config.cfg
	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "PasswordHistorySize "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			$test33 = $config_line[1]
			if($config_line[1] -ge "2")
			{
				#$data.code = "1"
				$projectdata = @{"true"="3.3 检查是否已正确配置`强制密码历史` >=2 $test33 TRUE";}
				echo "3.3	检查是否已正确配置`强制密码历史`	可选	建议调整	短期内使用历史密码会增加密码可猜测风险，同时参考等级保护标准，密码修改应不与近期修改相同。此检查项建议调整	>=2	$test33	TRUE		" >> $file_name
				$data['project']+=$projectdata
			}
			else
			{
				#$data.code = "0"
				$projectdata = @{"fail"="3.3 检查是否已正确配置`强制密码历史` >=2 $test33 FAIL";}
				echo "3.3	检查是否已正确配置`强制密码历史`	可选	建议调整	短期内使用历史密码会增加密码可猜测风险，同时参考等级保护标准，密码修改应不与近期修改相同。此检查项建议调整	>=2	$test33	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}
	}
}
else{
	$projectdata = @{"manual"="3.3 检查是否已正确配置`强制密码历史` >=2 $test33 MANUAL";}
	echo "3.3	检查是否已正确配置`强制密码历史`	可选	建议调整	短期内使用历史密码会增加密码可猜测风险，同时参考等级保护标准，密码修改应不与近期修改相同。此检查项建议调整	>=2	$test33	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}

#3.4 检查是否已正确配置帐户锁定时间

$all = $all +1
$ResetLockoutCount = Get-Content -path config.cfg | findstr ResetLockoutCount
if($ResetLockoutCount -ne $null){

	$config = Get-Content -path config.cfg
	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "ResetLockoutCount "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			$test34 = $config_line[1]
			#2021/04/28 修改标准值为[5,8]
			if(($config_line[1] -ge "5") -and ($config_line[1] -le "8"))
			{
				#$data.code = "1"
				$projectdata = @{"true"="3.4 检查是否已正确配置帐户锁定时间 >=1  $test34 TRUE";}
				echo "3.4	检查是否已正确配置帐户锁定时间	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	[5,8]	$test34	TRUE		" >> $file_name
				$data['project']+=$projectdata
			}
			else
			{
				#$data.code = "0"
				$projectdata = @{"fail"="3.4 检查是否已正确配置帐户锁定时间 >=1 $test34 FAIL";}
				echo "3.4	检查是否已正确配置帐户锁定时间	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	[5,8]	$test34	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}

	}

}
else{
	$projectdata = @{"manual"="3.4 检查是否已正确配置帐户锁定时间 >=1 $test34 MANUAL";}
	echo "3.4	检查是否已正确配置帐户锁定时间	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	[5,8]	null	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}





#3.5 检查是否已正确配置帐户锁定阈值
$all = $all +1
$LockoutBadCount = Get-Content -path config.cfg | findstr LockoutBadCount
if($LockoutBadCount -ne $null){

	$config = Get-Content -path config.cfg
	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "LockoutBadCount "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			$test35 = $config_line[1]
			#2021/04/28修改标准值为5
			if(($config_line[1] -eq "5"))
			{
				#$data.code = "1"
				$projectdata = @{"true"="3.5 检查是否已正确配置帐户锁定阈值 5 $test35 TRUE";}
				echo "3.5	检查是否已正确配置帐户锁定阈值	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	5	$test35	TRUE		" >> $file_name
				$data['project']+=$projectdata
			}
			else
			{
				#$data.code = "0"
				#$data.code = "0"
				$projectdata = @{"fail"="3.5 检查是否已正确配置帐户锁定阈值 5 $test35 FAIL";}
				echo "3.5	检查是否已正确配置帐户锁定阈值	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	5	$test35	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}

	}

}
else{
	$projectdata = @{"manual"="3.5 检查是否已正确配置帐户锁定阈值 5 $test35 MANUAL";}
	echo "3.5	检查是否已正确配置帐户锁定阈值	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	5	null	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}



#3.6 检查是否已正确配置“复位帐户锁定计数器”时间
$all = $all +1
$LockoutDuration = Get-Content -path config.cfg | findstr LockoutDuration
if($LockoutDuration -ne $null){

	$config = Get-Content -path config.cfg
	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "LockoutDuration "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			$test36 = $config_line[1]
			#2021/04/28修改标准值为5
			if(($config_line[1] -eq "5"))
			{
				#$data.code = "1"
				$projectdata = @{"true"="3.6 检查是否已正确配置复位帐户锁定计数器 5 $test36 TRUE";}
				echo "3.6	检查是否已正确配置复位帐户锁定计数器	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	5	$test36	TRUE		" >> $file_name
				$data['project']+=$projectdata
			}
			else
			{
				#$data.code = "0"
				$projectdata = @{"fail"="3.6 检查是否已正确配置复位帐户锁定计数器 5 $test36 FAIL";}
				echo "3.6	检查是否已正确配置复位帐户锁定计数器	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	5	$test36	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}

	}

}
else{
	$projectdata = @{"manual"="3.6 检查是否已正确配置复位帐户锁定计数器 5 $test36 MANUAL";}
	echo "3.6	检查是否已正确配置复位帐户锁定计数器	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	5	null	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}


##3.7 检查是否按照权限、责任创建、使用用户帐户
#$all = $all +1
##检查已启用的本地用户的个数
#$config = get-wmiobject -class win32_userAccount | select-object * | findstr /i "OK"
##get-wmiobject -class win32_userAccount | select-object * | findstr /i "Status Name" | findstr /v "__ Full Path"
##$config = get-wmiobject -class win32_userAccount | select-object *
##$config1 = get-content -path config.cfg
#$length = $config.Length
##echo "$config"
##echo "$length"
#if(($length -ne "23") -and ($length -ge "2")){
#	$projectdata = @{"true"="3.7 (非域环境)检查是否按照权限、责任创建、使用用户帐户 TRUE";}
#	$data['project']+=$projectdata
#}else{
#	$projectdata = @{"fail"="3.7 (非域环境)检查是否按照权限、责任创建、使用用户帐户 FAIL";}
#	$data['project']+=$projectdata
#}

##3.8 检查是否已更改管理员帐户名称
#$all = $all +1
#$NewAdministratorName = Get-Content -path config.cfg | findstr NewAdministratorName
#if($NewAdministratorName -ne $null){

#	$config = Get-Content -path config.cfg
#	for ($i=0; $i -lt $config.Length; $i++)
#	{
#		$config_line = $config[$i] -split "="
#		if(($config_line[0] -eq "NewAdministratorName "))
#		{
#			$config_line[1] = $config_line[1].Trim(' ').Trim('""')
#			#$a = $config_line[1].Trim(' ').Trim('""')
#			#echo "$a"
#			if(($config_line[1] -ne "Administrator"))
#			{

#				#$data.code = "1"
#				$projectdata = @{"true"="3.8 检查是否已更改管理员帐户名称 TRUE";}
#				$data['project']+=$projectdata
#			}
#			else
#			{

#				#$data.code = "0"
#				$projectdata = @{"fail"="3.8 检查是否已更改管理员帐户名称 FAIL";}
#				$data['project']+=$projectdata
#			}
#		}

#	}

#}
#else{
#	$projectdata = @{"manual"="3.8 检查是否已更改管理员帐户名称 MANUAL";}
#	$data['project']+=$projectdata
#}

#4 认证授权

#4.1 检查是否已删除可远程访问的注册表路径和子路经
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths'
$name = 'Machine'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction stop).$name
$test41 = $config
if ($config -ne $null){
	$projectdata = @{"fail"="4.1 检查是否已删除可远程访问的注册表路径和子路经 null $test41 FAIL";}
	echo "4.1	检查是否已删除可远程访问的注册表路径和子路经	可选	自行判断	注册表是设备配置信息到数据库，其中大部分信息是敏感到，恶意用户可以使用它来促进未授权活动。此项建议系统管理员根据系统情况自行判断	null	$test41	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
else{
	$projectdata = @{"true"="4.1 检查是否已删除可远程访问的注册表路径和子路经 null $test41 TRUE";}
	echo "4.1	检查是否已删除可远程访问的注册表路径和子路经	可选	自行判断	注册表是设备配置信息到数据库，其中大部分信息是敏感到，恶意用户可以使用它来促进未授权活动。此项建议系统管理员根据系统情况自行判断	null	$test41	TRUE		" >> $file_name
	$data['project']+=$projectdata
	
}




#4.2 检查是否已限制SAM匿名用户连接
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
$name = 'restrictanonymous'
$name2 = 'restrictanonymoussam'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
$config2 = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name2

if (($config -eq "1") -and ($config2 -eq "1")){
	$projectdata = @{"true"="4.2 检查是否已限制SAM匿名用户连接 restrictanonymous:$config/restrictanonymoussam:$config2 TRUE";}
	echo "4.2	检查是否已限制SAM匿名用户连接	可选	建议调整	未经授权到用户可以匿名列出账户名，存在社交工程共计或尝试猜测密码到风险。此检查项建议调整	restrictanonymous:1/restrictanonymoussam:1	restrictanonymous:$config/restrictanonymoussam:$config2	TRUE		" >> $file_name
	
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="4.2 检查是否已限制SAM匿名用户连接 restrictanonymous:$config/restrictanonymoussam:$config2 FAIL";}
	echo "4.2	检查是否已限制SAM匿名用户连接	可选	建议调整	未经授权到用户可以匿名列出账户名，存在社交工程共计或尝试猜测密码到风险。此检查项建议调整	restrictanonymous:1/restrictanonymoussam:1	restrictanonymous:$config/restrictanonymoussam:$config2	FAIL		" >> $file_name
	$data['project']+=$projectdata
}


#4.3 检查是否已限制可关闭系统的帐户和组
$all = $all +1
$shutdownPrivilege = Get-Content -path config.cfg | findstr SeShutdownPrivilege
if($shutdownPrivilege -ne $null){

	$config = Get-Content -path config.cfg
	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "SeShutdownPrivilege "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			#$a = $config_line[1]
			#echo "$a"
			$test43 = $config_line[1]
			if((($config_line[1] -eq "Administrator")) -or (($config_line[1] -eq "administrators")) -or (($config_line[1] -eq "S-1-5-32-544")) -or (($config_line[1] -eq "*S-1-5-32-544")) )
			{

				#$data.code = "1"
				$projectdata = @{"true"="4.3 检查是否已限制可关闭系统的帐户和组 Administrator/administrators/S-1-5-32-544 $test43 TRUE";}
				echo "4.3	检查是否已限制可关闭系统的帐户和组	可选	建议调整	可以关闭系统账户和组到必须是管理员角色。此检查项建议调整	Administrator/administrators/S-1-5-32-544	$test43	TRUE		" >> $file_name
				$data['project']+=$projectdata
			}
			else
			{

				#$data.code = "0"
				$projectdata = @{"fail"="4.3 检查是否已限制可关闭系统的帐户和组 Administrator/administrators/S-1-5-32-544 $test43 FAIL";}
				echo "4.3	检查是否已限制可关闭系统的帐户和组	可选	建议调整	可以关闭系统账户和组到必须是管理员角色。此检查项建议调整	Administrator/administrators/S-1-5-32-544	$test43	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}

	}

}
else{
	$projectdata = @{"manual"="3.8 检查是否已更改管理员帐户名称 Administrator/administrators/S-1-5-32-544 $test43 MANUAL";}
	echo "4.3	检查是否已限制可关闭系统的帐户和组	可选	建议调整	可以关闭系统账户和组到必须是管理员角色。此检查项建议调整	Administrator/administrators/S-1-5-32-544	null	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}


#4.4 检查是否已限制可从远端关闭系统的帐户和组
$all = $all +1

$config = Get-Content -path config.cfg

 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "SeRemoteShutdownPrivilege "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test44 = $config_line[1]
        if($config_line[1] -eq "*S-1-5-32-544")
        {
            $projectdata = @{"true"="4.4 检查是否已限制可从远端关闭系统的帐户和组 S-1-5-32-544 $test44 TRUE";}
			echo "4.4	检查是否已限制可从远端关闭系统的帐户和组	可选	建议调整	可以从远端关闭系统到账户和组必须是管理员组角色。此检查项建议调整	S-1-5-32-544	$test44	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
			$projectdata = @{"fail"="4.4 检查是否已限制可从远端关闭系统的帐户和组 FAIL";}
			echo "4.4	检查是否已限制可从远端关闭系统的帐户和组	可选	建议调整	可以从远端关闭系统到账户和组必须是管理员组角色。此检查项建议调整	S-1-5-32-544	$test44	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }
#4.5 检查是否已限制“取得文件或其他对象的所有权”的帐户和组
$all = $all +1
  $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "SeProfileSingleProcessPrivilege "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test45 = $config_line[1]
        if($config_line[1] -eq "*S-1-5-32-544")
        {
			$projectdata = @{"true"="4.5 检查是否已限制取得文件或其他对象的所有权的帐户和组 S-1-5-32-544 $test45 TRUE";}
			echo "4.5	检查是否已限制取得文件或其他对象的所有权的帐户和组	可选	建议调整	拥有系统文件或其他对象到所有权必须是管理员组角色。此检查项建议调整	S-1-5-32-544	$test45	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="4.5 检查是否已限制取得文件或其他对象的所有权的帐户和组 S-1-5-32-544 $test45 FAIL";}
			echo "4.5	检查是否已限制取得文件或其他对象的所有权的帐户和组	可选	建议调整	拥有系统文件或其他对象到所有权必须是管理员组角色。此检查项建议调整	S-1-5-32-544	$test45	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }


#4.6 检查是否已正确配置“允许本地登陆”策略
$all = $all +1

$projectdata = @{"manual"="4.6 检查是否已正确配置允许本地登陆策略(请管理员自查) MANUAL";}
echo "4.6	检查是否已正确配置允许本地登陆策略(请管理员自查)	可选	自行判断	通过此项配置项设置允许本地登录到用户和组，防范非授权本地登录。此项建议系统管理员根据系统情况自行判断	参考《windows系统安全配置基线》对应章节	null	MANUAL		" >> $file_name
$data['project']+=$projectdata


#4.7 检查是否已正确配置“从网络访问此计算机”策略
$all = $all +1
$projectdata = @{"manual"="4.7 检查是否已正确配置从网络访问此计算机策略(请管理员自查) MANUAL";}
echo "4.7	检查是否已正确配置从网络访问此计算机策略(请管理员自查)	可选	自行判断	通过此项配置项设置运行从网络访问计算机登录到用户和组，防范未知登录。此项建议系统管理员根据系统情况自行判断	参考《windows系统安全配置基线》对应章节	null	MANUAL		" >> $file_name
$data['project']+=$projectdata
<#  $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "SeNetworkLogonRight "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
        if($config_line[1] -eq "*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551")
        {
            $projectdata = @{"true"="4.7 检查是否已正确配置从网络访问此计算机策略  TRUE";}
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="4.7 检查是否已正确配置从网络访问此计算机策略  FAIL";}
			$data['project']+=$projectdata
        }
    }
  } #>

#4.8 检查是否已删除可匿名访问的共享和命名管道
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\LanmanServer\Parameters'
#可匿名访问的命名管道
$name = 'NullSessionPipes'
#可匿名访问的共享
$name2 = 'NullSessionShares'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
$config2 = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name2
<# $a = $config.Length
$b = $config2.Length
echo "$a"
echo "$b" #>
$test48 = $config.Length
$test48_1 = $config2.Length

if (($config.Length -eq 0) -and ($config2.Length -eq 0)){
	$projectdata = @{"true"="4.8 检查是否已删除可匿名访问的共享和命名管道 0，0	$test48,$test48_1 TRUE";}
	echo "4.8	检查是否已删除可匿名访问的共享和命名管道	可选	建议调整	启用此策略配置将未经过身份验证到用户限制为对除NullSessionPipes和NullSessionShares注册表项中列出的所有服务器管道和共享文件夹以外的所有服务器管道和共享文件夹到空回话访问，减少空会话漏洞风险。此检查项建议调整	0,0	$test48,$test48_1	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="4.8 检查是否已删除可匿名访问的共享和命名管道 0，0	$test48,$test48_1 FAIL";}
	echo "4.8	检查是否已删除可匿名访问的共享和命名管道	可选	建议调整	启用此策略配置将未经过身份验证到用户限制为对除NullSessionPipes和NullSessionShares注册表项中列出的所有服务器管道和共享文件夹以外的所有服务器管道和共享文件夹到空回话访问，减少空会话漏洞风险。此检查项建议调整	0,0	$test48,$test48_1	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#5 日至审计
#5.1 检查是否已正确配置审核（日志记录策略）
echo "5.1	检查是否已正确配置审核（日志记录策略）	可选	建议调整	服务器排错与维护是服务器开发必不可少到部分，故对日志文件到配置与管理尤为重要。此检查项建议调整	参考子项	参考子项	参考子项			" >> $file_name
$all = $all +1
#审核策略更改
 $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditSystemEvents "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test511 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.1 检查审核策略更改 3 $test511 TRUE";}
			echo "5.1.1	审核策略更改	可选	建议调整	详情参考父项5.1	3	$test511	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.1 检查审核策略更改 3 $test511 FAIL";}
			echo "5.1.1	审核策略更改	可选	建议调整	详情参考父项5.1	3	$test511	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }
#审核登陆事件
 $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditLogonEvents "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test512 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.2 检查审核登陆事件  3 $test512 TRUE";}
			echo "5.1.2	检查审核登陆事件	可选	建议调整	详情参考父项5.1	3	$test512	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.2 检查审核登陆事件  3 $test512 FAIL";}
			echo "5.1.2	检查审核登陆事件	可选	建议调整	详情参考父项5.1	3	$test512	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }
 #审核对象访问
  $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditObjectAccess "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test513 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.3 检查审核对象访问  3 $test513 TRUE";}
			echo "5.1.3	检查审核对象访问	可选	建议调整	详情参考父项5.1	3	$test513	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.3 检查审核对象访问  3 $test513 FAIL";}
			echo "5.1.3	检查审核对象访问	可选	建议调整	详情参考父项5.1	3	$test513	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }

 #审核进程跟踪
  $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditProcessTracking "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test514 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.4 检查审核进程跟踪  3 $test514 TRUE";}
			echo "5.1.4	检查审核进程跟踪	可选	建议调整	详情参考父项5.1	3	$test514	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.4 检查审核进程跟踪  3 $test514 FAIL";}
			echo "5.1.4	检查审核进程跟踪	可选	建议调整	详情参考父项5.1	3	$test514	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }
  #审核目录服务访问
   $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditDSAccess "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test515 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.5 检查审核目录服务访问 3 $test515 TRUE";}
			echo "5.1.5	检查审核目录服务访问	可选	建议调整	详情参考父项5.1	3	$test515	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.5 检查审核目录服务访问 3 $test515 FAIL";}
			echo "5.1.5	检查审核目录服务访问	可选	建议调整	详情参考父项5.1	3	$test515	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }
 #审核特权使用
  $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditPrivilegeUse "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test516 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.6 检查审核特权使用 3 $test516 TRUE";}
			echo "5.1.6	检查审核特权使用	可选	建议调整	详情参考父项5.1	3	$test516	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.6 检查审核特权使用 3 $test516 FAIL";}
			echo "5.1.6	检查审核特权使用	可选	建议调整	详情参考父项5.1	3	$test516	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }
  #审核系统事件
   $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditSystemEvents "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test517 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.7 检查审核系统事件 3 $test517 TRUE";}
			echo "5.1.7	检查审核系统事件	可选	建议调整	详情参考父项5.1	3	$test517	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.7 检查审核系统事件 3 $test517 FAIL";}
			echo "5.1.7	检查审核系统事件	可选	建议调整	详情参考父项5.1	3	$test517	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
}
#审核帐户登陆事件
 $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditAccountLogon "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test518 = $config_line[1]
		#“2”是windows2016，改为“3”尝试
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.8 检查审核帐户登陆事件 3 $test518 TRUE";}
			echo "5.1.8	检查审核帐户登陆事件	可选	建议调整	详情参考父项5.1	3	$test518	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.8 检查审核帐户登陆事件 3 $test518 FAIL";}
			echo "5.1.8	检查审核帐户登陆事件	可选	建议调整	详情参考父项5.1	3	$test518	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
}
#审核帐户管理
 $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditAccountManage "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test519 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.9 检查审核帐户管理 3  $test519 TRUE";}
			echo "5.1.9	检查审核帐户管理	可选	建议调整	详情参考父项5.1	3	$test519	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.9 检查审核帐户管理 3 $test519 FAIL";}
			echo "5.1.9	检查审核帐户管理	可选	建议调整	详情参考父项5.1	3	$test519	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
}
#5.2 检查是否已正确配置应用程序日志
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\eventlog\Application'
#按需要覆盖事件
$name = 'Retention'
#日志最大大小
$name1 = 'MaxSize'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
$config1 = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name1
#echo "$config1"
if (($config -eq 0) -and ($config1 -ge 8388608)){
	$projectdata = @{"true"="5.2 检查是否已正确配置应用程序日志 0,>=8388608 $config,$config1  TRUE";}
	echo "5.2	检查是否已正确配置应用程序日志	可选	建议调整	服务器排错与维护是服务器开发必不可少到部分，故对日志文件到配置与管理尤为重要。此检查项建议调整	0,>=8388608	$config,$config1	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="5.2 检查是否已正确配置应用程序日志 0,>=8388608 $config,$config1 FAIL";}
	echo "5.2	检查是否已正确配置应用程序日志	可选	建议调整	服务器排错与维护是服务器开发必不可少到部分，故对日志文件到配置与管理尤为重要。此检查项建议调整	0,>=8388608	$config,$config1	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#5.3 检查是否已正确配置系统日志
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\eventlog\System'
#按需要覆盖事件
$name = 'Retention'
#日志最大大小
$name1 = 'MaxSize'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
$config1 = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name1
#echo "$config1"
if (($config -eq 0) -and ($config1 -ge 8388608)){
	$projectdata = @{"true"="5.3 检查是否已正确配置系统日志 0,>=8388608 $config,$config1 TRUE";}
	echo "5.3	检查是否已正确配置系统日志	可选	建议调整	服务器排错与维护是服务器开发必不可少到部分，故对日志文件到配置与管理尤为重要。此检查项建议调整	0,>=8388608	$config,$config1	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="5.3 检查是否已正确配置系统日志 0,>=8388608 $config,$config1 FAIL";}
	echo "5.3	检查是否已正确配置系统日志	可选	建议调整	服务器排错与维护是服务器开发必不可少到部分，故对日志文件到配置与管理尤为重要。此检查项建议调整	0,>=8388608	$config,$config1	FAIL		" >> $file_name
	$data['project']+=$projectdata
}

#5.4 检查是否已正确配置安全日志
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\eventlog\Security'
#按需要覆盖事件
$name = 'Retention'
#日志最大大小
$name1 = 'MaxSize'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
$config1 = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name1
#echo "$config1"
if (($config -eq 0) -and ($config1 -ge 8388608)){
	$projectdata = @{"true"="5.4 检查是否已正确配置安全日志 0,>=8388608 $config,$config1 TRUE";}
	echo "5.4	检查是否已正确配置安全日志	可选	建议调整	服务器排错与维护是服务器开发必不可少到部分，故对日志文件到配置与管理尤为重要。此检查项建议调整	0,>=8388608	$config,$config1	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="5.4 检查是否已正确配置安全日志 0,>=8388608 $config,$config1 FAIL";}
	echo "5.4	检查是否已正确配置安全日志	可选	建议调整	服务器排错与维护是服务器开发必不可少到部分，故对日志文件到配置与管理尤为重要。此检查项建议调整	0,>=8388608	$config,$config1	FAIL		" >> $file_name
	$data['project']+=$projectdata
}

#6 协议安全
#6.1 检查是否已修改默认的远程rdp服务端口
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

$name = 'PortNumber'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
#echo "$config"
if ($config -ne 3389){
	$projectdata = @{"true"="6.1 检查是否已修改默认的远程rdp服务端口 !=3389 $config TRUE";}
	echo "6.1	检查是否已正确配置安全日志	可选	自行判断	应修改默认RDP端口，避免windows默认端口被猜测，此项建议系统管理员根据系统情况自行判断	!=3389	$config	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="6.1 检查是否已修改默认的远程rdp服务端口 !=3389 $config FAIL";}
	echo "6.1	检查是否已正确配置安全日志	可选	自行判断	应修改默认RDP端口，避免windows默认端口被猜测，此项建议系统管理员根据系统情况自行判断	!=3389	$config	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#6.2 检查是否已启用并正确配置源路由攻击保护
$all = $all +1
$dsr = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" | findstr DisableIPSourceRouting
if ($dsr -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters'

	$name = 'DisableIPSourceRouting'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 2){
		$projectdata = @{"true"="6.2 检查是否已启用并正确配置源路由攻击保护 2 $config TRUE";}
		echo "6.2	检查是否已启用并正确配置源路由攻击保护	可选	建议调整	应正确配置源路由攻击保护预防源路由攻击，包括源地址欺骗、IP欺骗等。此检查项建议调整	2	$config	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.2 检查是否已启用并正确配置源路由攻击保护 2 $config FAIL";}
		echo "6.2	检查是否已启用并正确配置源路由攻击保护	可选	建议调整	应正确配置源路由攻击保护预防源路由攻击，包括源地址欺骗、IP欺骗等。此检查项建议调整	2	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.2 检查是否已启用并正确配置源路由攻击保护(请按照基线文档执行用例) 2 $dsr FAIL";}
	echo "6.2	检查是否已启用并正确配置源路由攻击保护	可选	建议调整	应正确配置源路由攻击保护预防源路由攻击，包括源地址欺骗、IP欺骗等。此检查项建议调整	2	$dsr	FAIL		" >> $file_name
	
	$data['project']+=$projectdata
}
#6.3 检查是否已开启Windows防火墙
$all = $all +1
$projectdata = @{"manual"="6.3 检查是否已开启Windows防火墙(请管理员自查)  MANUAL";}
echo "6.3	检查是否已开启Windows防火墙(请管理员自查)	可选	自行判断	服务器应开启防火墙检测和抵御外部威胁，考虑到部分服务器反向代理情况。此项建议系统管理员根据系统情况自行判断	已启用	null	MANUAL		" >> $file_name
$data['project']+=$projectdata

#6.4 检查是否已启用并正确配置SYN攻击保护
echo "6.4	检查是否已启用并正确配置SYN攻击保护	可选	建议调整	应配置相关策略预防SYN洪水攻击，防止服务器停止响应与崩溃。此检查项建议调整	参考子项	参考子项	参考子项		" >> $file_name
$all = $all +1
#检查是否已启用SYN攻击保护
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" | findstr SynAttackProtect
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters'

	$name = 'SynAttackProtect'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 1){
		$projectdata = @{"true"="6.4.1 检查是否已启用SYN攻击保护 1 $config TRUE";}
		echo "6.4.1	检查是否已启用SYN攻击保护	可选	建议调整	详情参考父项6.4	1	$config	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.4.1 检查是否已启用SYN攻击保护 1 $config FAIL";}
		echo "6.4.1	检查是否已启用SYN攻击保护	可选	建议调整	详情参考父项6.4	1	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.4.1 检查是否已启用SYN攻击保护(请按照基线文档执行用例) 1 $syn FAIL";}
	echo "6.4.1	检查是否已启用SYN攻击保护(请按照基线文档执行用例)	可选	建议调整	详情参考父项6.4	1	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}

#检查TCP连接请求阈值

$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" | findstr TcpMaxPortsExhausted
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters'

	$name = 'TcpMaxPortsExhausted'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 5){
		$projectdata = @{"true"="6.4.2 检查TCP连接请求阈值 5 $config TRUE";}
		echo "6.4.2	检查TCP连接请求阈值	可选	建议调整	详情参考父项6.4	5	$config	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.4.2 检查TCP连接请求阈值 5 $config FAIL";}
		echo "6.4.2	检查TCP连接请求阈值	可选	建议调整	详情参考父项6.4	5	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.4.2 检查TCP连接请求阈值(请按照基线文档执行用例) 5 $syn FAIL";}
	echo "6.4.2	检查TCP连接请求阈值(请按照基线文档执行用例)	可选	建议调整	详情参考父项6.4	5	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#检查取消尝试响应 SYN 请求之前要重新传输 SYN-ACK 的次数
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" | findstr TcpMaxConnectResponseRetransmissions
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters'

	$name = 'TcpMaxConnectResponseRetransmissions'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 2){
	
		$projectdata = @{"true"="6.4.3 检查取消尝试响应SYN请求之前要重新传输SYN-ACK的次数 2 $config TRUE";}
		echo "6.4.3	检查取消尝试响应SYN请求之前要重新传输SYN-ACK的次数	可选	建议调整	详情参考父项6.4	2	$config	TRUE		" >> $file_name
		
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.4.3 检查取消尝试响应SYN请求之前要重新传输SYN-ACK的次数 2 $config FAIL";}
		echo "6.4.3	检查取消尝试响应SYN请求之前要重新传输SYN-ACK的次数	可选	建议调整	详情参考父项6.4	2	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.4.3 检查取消尝试响应SYN请求之前要重新传输SYN-ACK的次数(请按照基线文档执行用例) 2 $syn FAIL";}
	echo "6.4.3	检查取消尝试响应SYN请求之前要重新传输SYN-ACK的次数(请按照基线文档执行用例)	可选	建议调整	详情参考父项6.4	2	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}

#检查处于SYN_RCVD 状态下的 TCP 连接阈值
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" | findstr TcpMaxHalfOpen
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters'

	$name = 'TcpMaxHalfOpen'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 500){
		$projectdata = @{"true"="6.4.4 检查处于SYN_RCVD状态下的TCP连接阈值 500 $config TRUE";}
		echo "6.4.4	检查处于SYN_RCVD状态下的TCP连接阈值	可选	建议调整	详情参考父项6.4	500	$config	TRUE		" >> $file_name
		
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.4.4 检查处于SYN_RCVD状态下的TCP连接阈值 500 $config FAIL";}
		echo "6.4.4	检查处于SYN_RCVD状态下的TCP连接阈值	可选	建议调整	详情参考父项6.4	500	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.4.4 检查处于SYN_RCVD状态下的TCP连接阈值(请按照基线文档执行用例) 500 $syn FAIL";}
	echo "6.4.4	检查处于SYN_RCVD状态下的TCP连接阈值	可选	建议调整	详情参考父项6.4	500	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}


# 检查处于SYN_RCVD 状态下，且至少已经进行了一次重新传输的TCP连接阈值
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" | findstr TcpMaxHalfOpenRetried
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters'

	$name = 'TcpMaxHalfOpenRetried'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 400){
		$projectdata = @{"true"="6.4.5 检查处于SYN_RCVD状态下,且至少已经进行了一次重新传输的TCP连接阈值 400 $config TRUE";}
		echo "6.4.5	检查处于SYN_RCVD状态下,且至少已经进行了一次重新传输的TCP连接阈值	可选	建议调整	详情参考父项6.4	400	$config	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.4.5 检查处于SYN_RCVD状态下,且至少已经进行了一次重新传输的TCP连接阈值  FAIL";}
		echo "6.4.5	检查处于SYN_RCVD状态下,且至少已经进行了一次重新传输的TCP连接阈值	可选	建议调整	详情参考父项6.4	400	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.4.5 检查处于SYN_RCVD状态下，且至少已经进行了一次重新传输的TCP连接阈值(请按照基线文档执行用例) 400 $syn FAIL";}
	echo "6.4.5	检查处于SYN_RCVD状态下,且至少已经进行了一次重新传输的TCP连接阈值	可选	建议调整	详情参考父项6.4	400	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}

#6.5 检查是否已启用并正确配置ICMP攻击保护
$all = $all +1
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" | findstr EnableICMPRedirect
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters'

	$name = 'EnableICMPRedirect'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 0){
		$projectdata = @{"true"="6.5 检查是否已启用并正确配置ICMP攻击保护 0 $config TRUE";}
		echo "6.5	检查是否已启用并正确配置ICMP攻击保护	可选	建议调整	应配置ICMP攻击保护预防ICMP攻击，防止DOS攻击导致服务器停止响应与奔溃。此检查项建议调整	0	$config	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.5 检查是否已启用并正确配置ICMP攻击保护 0 $config FAIL";}
		echo "6.5	检查是否已启用并正确配置ICMP攻击保护	可选	建议调整	应配置ICMP攻击保护预防ICMP攻击，防止DOS攻击导致服务器停止响应与奔溃。此检查项建议调整	0	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.5 检查是否已启用并正确配置ICMP攻击保护(请按照基线文档执行用例) 0 $syn FAIL";}
	echo "6.5	检查是否已启用并正确配置ICMP攻击保护	可选	建议调整	应配置ICMP攻击保护预防ICMP攻击，防止DOS攻击导致服务器停止响应与奔溃。此检查项建议调整	0	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#6.6 检查是否已禁用失效网关检测
$all = $all +1
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" | findstr EnableDeadGWDetect
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters'

	$name = 'EnableDeadGWDetect'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 0){
		$projectdata = @{"true"="6.6 检查是否已禁用失效网关检测 0 $config TRUE";}
		echo "6.6	检查是否已禁用失效网关检测	可选	建议调整	应禁用失效网关检测，防止DOS攻击导致服务器停止响应与崩溃。此检查项建议调整	0	$config	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.6 检查是否已禁用失效网关检测 0 $config FAIL";}
		echo "6.6	检查是否已禁用失效网关检测	可选	建议调整	应禁用失效网关检测，防止DOS攻击导致服务器停止响应与崩溃。此检查项建议调整	0	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.6 检查是否已禁用失效网关检测(请按照基线文档执行用例) 0 $syn FAIL";}
	echo "6.6	检查是否已禁用失效网关检测	可选	建议调整	应禁用失效网关检测，防止DOS攻击导致服务器停止响应与崩溃。此检查项建议调整	0	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#6.7 检查是否已正确配置重传单独数据片段的次数
$all = $all +1
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" | findstr TcpMaxDataRetransmissions
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters'

	$name = 'TcpMaxDataRetransmissions'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 2){
		$projectdata = @{"true"="6.7 检查是否已正确配置重传单独数据片段的次数  2 $config TRUE";}
		echo "6.7	检查是否已正确配置重传单独数据片段的次数	可选	建议调整	应配置重传次数，防止频繁重传导致服务器停止响应与崩溃。此检查项建议调整	2	$config	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.7 检查是否已正确配置重传单独数据片段的次数  2 $config FAIL";}
		echo "6.7	检查是否已正确配置重传单独数据片段的次数	可选	建议调整	应配置重传次数，防止频繁重传导致服务器停止响应与崩溃。此检查项建议调整	2	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.7 检查是否已正确配置重传单独数据片段的次数(请按照基线文档执行用例) 2 $syn FAIL";}
	echo "6.7	检查是否已正确配置重传单独数据片段的次数	可选	建议调整	应配置重传次数，防止频繁重传导致服务器停止响应与崩溃。此检查项建议调整	2	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#6.8 检查是否已禁用路由发现功能
$all = $all +1
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" | findstr PerformRouterDiscovery
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters'

	$name = 'PerformRouterDiscovery'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 0){
		$projectdata = @{"true"="6.8 检查是否已禁用路由发现功能 0 $config TRUE";}
		echo "6.8	检查是否已禁用路由发现功能	可选	建议调整	应禁用路由发现功能，防止DOS攻击导致服务器停止响应与奔溃。此检查项建议调整	0	$config	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.8 检查是否已禁用路由发现功能 0 $config FAIL";}
		echo "6.8	检查是否已禁用路由发现功能	可选	建议调整	应禁用路由发现功能，防止DOS攻击导致服务器停止响应与奔溃。此检查项建议调整	0	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.8 检查是否已禁用路由发现功能(请按照基线文档执行用例) 0 $syn FAIL";}
	echo "6.8	检查是否已禁用路由发现功能	可选	建议调整	应禁用路由发现功能，防止DOS攻击导致服务器停止响应与奔溃。此检查项建议调整	0	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#6.9 检查是否已正确配置TCP“连接存活时间”
$all = $all +1
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" | findstr KeepAliveTime
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'

	$name = 'KeepAliveTime'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -le 300000){
		$projectdata = @{"true"="6.9 检查是否已正确配置TCP连接存活时间 300000 $config TRUE";}
		echo "6.9	检查是否已正确配置TCP连接存活时间	可选	建议调整	链接存活时间过长，会加剧网络拥塞程度，可能导致服务器停止响应与崩溃。此检查项建议调整	300000	$config	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.9 检查是否已正确配置TCP连接存活时间 300000 $config FAIL";}
		echo "6.9	检查是否已正确配置TCP连接存活时间	可选	建议调整	链接存活时间过长，会加剧网络拥塞程度，可能导致服务器停止响应与崩溃。此检查项建议调整	300000	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.9 检查是否已正确配置TCP连接存活时间(请按照基线文档执行用例) 300000 $syn FAIL";}
	echo "6.9	检查是否已正确配置TCP连接存活时间	可选	建议调整	链接存活时间过长，会加剧网络拥塞程度，可能导致服务器停止响应与崩溃。此检查项建议调整	300000	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}

#6.10 检查是否已启用并正确配置TCP碎片攻击保护
$all = $all +1
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" | findstr EnablePMTUDiscovery
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters'

	$name = 'EnablePMTUDiscovery'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 0){
		$projectdata = @{"true"="6.10 检查是否已启用并正确配置TCP碎片攻击保护  0 $config TRUE";}
		echo "6.1 0	检查是否已启用并正确配置TCP碎片攻击保护	可选	建议调整	攻击者有意发送大型ip碎片，可能导致服务器停止响应与崩溃。此检查项建议调整	0	$config	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="6.10 检查是否已启用并正确配置TCP碎片攻击保护 0 $config FAIL";}
		echo "6.1 0	检查是否已启用并正确配置TCP碎片攻击保护	可选	建议调整	攻击者有意发送大型ip碎片，可能导致服务器停止响应与崩溃。此检查项建议调整	0	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="6.10 检查是否已启用并正确配置TCP碎片攻击保护(请按照基线文档执行用例) 0 $syn FAIL";}
	echo "6.1 0	检查是否已启用并正确配置TCP碎片攻击保护	可选	建议调整	攻击者有意发送大型ip碎片，可能导致服务器停止响应与崩溃。此检查项建议调整	0	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
##6.11 检查是否已启用TCP/IP筛选功能
#$all = $all +1
#$projectdata = @{"manual"="6.11 检查是否已启用TCP/IP筛选功能(请管理员自查,此项配置支持windows2000\windowsXP\windwos2003\windows2003r2)  MANUAL";}
#$data['project']+=$projectdata



#6.11 检查是否已删除SNMP服务的默认public团体
$all = $all +1
$snmp = get-service | findstr /c:'SNMP Service'
if($snmp -eq $null){

	$projectdata = @{"true"="6.11 检查是否已删除SNMP服务的默认public团体 null $snmp TRUE";}
	echo "6.11	检查是否已删除SNMP服务的默认public团体	可选	建议调整	snmp服务到默认public团体字，黑客可以利用此默认团体进行信息收集。此检查项建议调整	null	$snmp	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"manual"="6.11 检查是否已删除SNMP服务的默认public团体(请管理员自查) null $snmp MANUAL";}
	echo "6.11	检查是否已删除SNMP服务的默认public团体	可选	建议调整	snmp服务到默认public团体字，黑客可以利用此默认团体进行信息收集。此检查项建议调整	null	$snmp	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}




#7 其他配置操作
#7.1 检查是否已安装防病毒软件
$all = $all +1
$projectdata = @{"manual"="7.1 检查是否已安装防病毒软件(请管理员自查)  MANUAL";}
echo "7.1	检查是否已安装防病毒软件(请管理员自查)	可选	自行判断	应根据系统自身到情况决定是否安装防病毒软件。此项建议系统管理员根据系统情况自行判断	已安装	null	MANUAL		" >> $file_name
$data['project']+=$projectdata
#7.2 检查是否已启用并正确配置Windows自动更新
$all = $all +1
$projectdata = @{"manual"="7.２ 检查是否已启用并正确配置Windows自动更新(请管理员自查)  MANUAL";}
echo "7.2	检查是否已启用并正确配置Windows自动更新(请管理员自查)	可选	自行判断	应及时的安装系统补丁，提高操作系统到稳定性。此项建议系统管理员根据系统情况自行判断	已配置	null	MANUAL		" >> $file_name
$data['project']+=$projectdata


#7.3 检查是否已启用“不显示最后的用户名”策略
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$name = 'dontdisplaylastusername'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
#echo "$config"
if ($config -eq 1){
	$projectdata = @{"true"="7.3 检查是否已启用不显示最后的用户名 1 $config TRUE";}
	echo "7.3	检查是否已启用不显示最后的用户名	可选	建议调整	应配置该策略防止用户名信息泄露。此检查项建议调整	1	$config	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="7.3 检查是否已启用不显示最后的用户名 1 $config FAIL";}
	echo "7.3	检查是否已启用不显示最后的用户名	可选	建议调整	应配置该策略防止用户名信息泄露。此检查项建议调整	1	$config	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#7.4 检查是否已正确配置“提示用户在密码过期之前进行更改”策略
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$name = 'PasswordExpiryWarning'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
#echo "$config"
if ($config -ge 14){
	$projectdata = @{"true"="7.4 检查是否已正确配置`提示用户在密码过期之前进行更改`策略 14 $config TRUE";}
	echo "7.4	检查是否已正确配置`提示用户在密码过期之前进行更改`策略	可选	建议调整	应配置密码过期提醒策略防止密码过期无法登陆。此检查项建议调整	14	$config	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="7.4 检查是否已正确配置`提示用户在密码过期之前进行更改`策略 14 $config FAIL";}
	echo "7.4	检查是否已正确配置`提示用户在密码过期之前进行更改`策略	可选	建议调整	应配置密码过期提醒策略防止密码过期无法登陆。此检查项建议调整	14	$config	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#7.5 检查是否已正确配置“锁定会话时显示用户信息”策略
$all = $all +1
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | findstr DontDisplayLockedUserId
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

	$name = 'DontDisplayLockedUserId'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	#echo "$config"
	if ($config -eq 3){
		$projectdata = @{"true"="7.5 检查是否已启用并正确配置锁定会话时显示用户信息 3 $config TRUE";}
		echo "7.5	检查是否已启用并正确配置锁定会话时显示用户信息	可选	建议调整	在锁定会话时，系统不应显示用户信息。此检查项建议调整	3	$config	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="7.5 检查是否已启用并正确配置锁定会话时显示用户信息 3 $config FAIL";}
		echo "7.5	检查是否已启用并正确配置锁定会话时显示用户信息	可选	建议调整	在锁定会话时，系统不应显示用户信息。此检查项建议调整	3	$config	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="7.5 检查是否已启用并正确配置锁定会话时显示用户信息(请按照基线文档执行用例) 3 $syn FAIL";}
	echo "7.5	检查是否已启用并正确配置锁定会话时显示用户信息	可选	建议调整	在锁定会话时，系统不应显示用户信息。此检查项建议调整	3	$syn	TRUE		" >> $file_name
	$data['project']+=$projectdata
}
#7.6 检查是否已禁用Windows硬盘默认共享
$all = $all +1
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" | findstr DontDisplayLockedUserId
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters'

	$name = 'AutoShareServer'
	$name1 = 'AutoShareWks'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	$config1 = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name1
	#echo "$config"
	if (($config -eq 0) -and ($config1 -eq 0)){
		$projectdata = @{"true"="7.6 检查是否已禁用Windows硬盘默认共享  0,0 $congif,$config1 TRUE";}
		echo "7.6	检查是否已禁用Windows硬盘默认共享	可选	自行判断	（适用非域环境）部分操作系统提供了默认共享功能，如果服务器联网，那么网络上到任何人都可以通过共享盘，随意访问该电脑。此项建议系统管理员根据系统情况自行判断	0,0	$config,$config1	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="7.6 检查是否已禁用Windows硬盘默认共享 0,0 $congif,$config1 FAIL";}
		echo "7.6	检查是否已禁用Windows硬盘默认共享	可选	自行判断	（适用非域环境）部分操作系统提供了默认共享功能，如果服务器联网，那么网络上到任何人都可以通过共享盘，随意访问该电脑。此项建议系统管理员根据系统情况自行判断	0,0	$config,$config1	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}

}
else{
	$projectdata = @{"fail"="7.6 检查是否已禁用Windows硬盘默认共享(请按照基线文档执行用例) 0,0 $syn FAIL";}
	echo "7.6	检查是否已禁用Windows硬盘默认共享	可选	自行判断	（适用非域环境）部分操作系统提供了默认共享功能，如果服务器联网，那么网络上到任何人都可以通过共享盘，随意访问该电脑。此项建议系统管理员根据系统情况自行判断	0,0	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#7.7 检查是否已启用并正确配置屏幕保护程序
$all = $all +1
#屏幕自动保护程序
echo "7.7	检查是否已启用并正确配置屏幕保护程序	可选	建议调整	在无操作到一段时间内，系统应开启屏幕保护程序。此检查项建议调整	参考子项	参考子项	参考子项		" >> $file_name
$Key = 'HKEY_CURRENT_USER\Control Panel\Desktop'
$name = "ScreenSaveActive"
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$name
if($config -eq "1"){
    $projectdata = @{"true"="7.7.1 检查是否已启用并正确配置屏幕保护程序 1 $config TRUE";}
	echo "7.7.1	检查是否已启用并正确配置屏幕保护程序	可选	建议调整	详情参考父项7.7	1	$config	TRUE		" >> $file_name
	$data['project']+=$projectdata
}
else{
    $projectdata = @{"fail"="7.7.1 检查是否已启用并正确配置屏幕保护程序 1 $config FAIL";}
	echo "7.7.1	检查是否已启用并正确配置屏幕保护程序	可选	建议调整	详情参考父项7.7	1	$config	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#检查屏幕保护程序等待时间

$Key = 'HKEY_CURRENT_USER\Control Panel\Desktop'
$name = "ScreenSaveTimeOut"
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$name
if($config -le 300)
        {
            $projectdata = @{"true"="7.7.2 检查屏幕保护程序等待时间  <=300 $config TRUE";}
			echo "7.7.2	检查屏幕保护程序等待时间	可选	建议调整	详情参考父项7.7	<=300	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.7.2 检查屏幕保护程序等待时间 <=300 $config FAIL";}
			echo "7.7.2	检查屏幕保护程序等待时间	可选	建议调整	详情参考父项7.7	<=300	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
#检查是否已启用在恢复时显示登陆界面
$Key = 'HKEY_CURRENT_USER\Control Panel\Desktop'
$name = "ScreenSaverIsSecure"
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$name
if($config -eq "1")
        {
            $projectdata = @{"true"="7.7.3 检查是否已启用在恢复时显示登陆界面  TRUE";}
			echo "7.7.3	检查是否已启用在恢复时显示登陆界面	可选	建议调整	详情参考父项7.7	1	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.7.3 检查是否已启用在恢复时显示登陆界面  FAIL";}
			echo "7.7.3	检查是否已启用在恢复时显示登陆界面	可选	建议调整	详情参考父项7.7	1	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }


#7.8 检查是否已启用并正确配置Windows网络时间同步服务(NTP)
$all = $all +1
$Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer'
$Name = 'Enabled'
 $config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
   if($config -eq "0")
        {
            $projectdata = @{"true"="7.8 检查是否已启用并正确配置Windows网络时间同步服务 0 $config TRUE";}
			echo "7.8	检查是否已启用并正确配置Windows网络时间同步服务	可选	建议调整	应保证windows系统到时间同步，提高系统日志到准确性。此检查项建议调整	0	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.8 检查是否已启用并正确配置Windows网络时间同步服务 0 $config FAIL";}
			echo "7.8	检查是否已启用并正确配置Windows网络时间同步服务	可选	建议调整	应保证windows系统到时间同步，提高系统日志到准确性。此检查项建议调整	0	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
#7.9 检查是否已关闭Windows自动播放
$all = $all +1
$projectdata = @{"manual"="7.9 检查是否已关闭Windows自动播放(请管理员自查)  MANUAL";}
echo "7.9	检查是否已关闭Windows自动播放(请管理员自查)	可选	自行判断	极客中通过恶意代码写在U盘上，如果系统开启了自动播放功能，那么只要这些U盘插入在服务器上，该服务器就会感染到U盘上到病毒。此项建议系统管理员根据系统情况自行判断	启用	null	MANUAL		" >> $file_name
$data['project']+=$projectdata
#7.10 检查是否已关闭不必要的服务-DHCP Client
$all = $all +1
$dhcp = get-service | findstr /c:'DHCP Client' | findstr Running
if($dhcp -eq $null){
	$projectdata = @{"true"="7.10 检查是否已关闭不必要的服务-DHCPClient null $dhcp TRUE";}
	echo "7.1 0	检查是否已关闭不必要的服务-DHCPClient	可选	自行判断	攻击者可以伪造DHCP服务器，提供错误到信息给客户端到网卡。也可以伪造MAC地址，持续发送Discovery包，耗尽IP地址池，如无使用必要，请关闭此服务。此项建议系统管理员根据系统情况自行判断	null	$dhcp	TRUE		" >> $file_name
	$data['project']+=$projectdata
}
else{
	$projectdata = @{"true"="7.10 检查是否已关闭不必要的服务-DHCPClient null $dhcp FAIL";}
	echo "7.1 0	检查是否已关闭不必要的服务-DHCPClient	可选	自行判断	攻击者可以伪造DHCP服务器，提供错误到信息给客户端到网卡。也可以伪造MAC地址，持续发送Discovery包，耗尽IP地址池，如无使用必要，请关闭此服务。此项建议系统管理员根据系统情况自行判断	null	$dhcp	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#7.11 检查系统是否已安装最新补丁包和补丁
$all = $all +1
$projectdata = @{"manual"="7.11 检查系统是否已安装最新补丁包和补丁(请管理员自查)  MANUAL";}
echo "7.11	检查系统是否已安装最新补丁包和补丁	一般	自行判断	应及时到安装系统补丁，提高操作系统到稳定性。此项建议系统管理员根据系统情况自行判断	已安装最新补丁	null	MANUAL		" >> $file_name
$data['project']+=$projectdata
##7.12 检查所有磁盘分区的文件系统格式
#$all = $all +1

#$projectdata = @{"manual"="7.12 检查所有磁盘分区的文件系统格式(请管理员自查)  MANUAL";}
#$data['project']+=$projectdata

#7.12 检查是否已正确配置服务器在暂停会话前所需的空闲时间量
$all = $all +1
$Key = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\LanmanServer\Parameters'
$Name = 'autodisconnect'
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
#echo "$config"
   if($config -eq 15)
        {
            $projectdata = @{"true"="7.12 检查是否已正确配置服务器在暂停会话前所需的空闲时间量 15 $config TRUE";}
			echo "7.12	检查是否已正确配置服务器在暂停会话前所需的空闲时间量	可选	建议调整	SMB会话会占用服务器资源，攻击者可能反复建立SMB会话导致系统缓慢或无响应。此检查项建议调整	15	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.13 检查是否已正确配置服务器在暂停会话前所需的空闲时间量 15 $config FAIL";}
			echo "7.12	检查是否已正确配置服务器在暂停会话前所需的空闲时间量	可选	建议调整	SMB会话会占用服务器资源，攻击者可能反复建立SMB会话导致系统缓慢或无响应。此检查项建议调整	15	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
#7.14 检查是否已启用“当登录时间用完时自动注销用户”策略
$all = $all +1
$Key = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\LanmanServer\Parameters'
$Name = 'enableforcedlogoff'
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
#echo "$config"
   if($config -eq 1)
        {
            $projectdata = @{"true"="7.13 检查是否已启用当登录时间用完时自动注销用户量 1 $config TRUE";}
			echo "7.13	检查是否已启用当登录时间用完时自动注销用户量	可选	自行判断	登录时间完应自动注销用户，此项建议系统管理员根据系统情况自行判断	1	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.14 检查是否已启用当登录时间用完时自动注销用户量 1 $config FAIL";}
			echo "7.13	检查是否已启用当登录时间用完时自动注销用户量	可选	自行判断	登录时间完应自动注销用户，此项建议系统管理员根据系统情况自行判断	1	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
#7.15 域环境：检查是否已启用“需要域控制器身份验证以解锁工作站”策略
#$all = $all +1
#$Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
#$Name = 'ForceUnlockLogon'
#$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
##echo "$config"
#   if($config -eq 1)
#        {
 #           $projectdata = @{"true"="7.14 检查是否已启需要域控制器身份验证以解锁工作站 1 $config TRUE";}
	#		echo "7.14	检查是否已启需要域控制器身份验证以解锁工作站	可选	建议调整	适用于域环境，此检查项建议调整	1	$config	TRUE		" >> $file_name
	#		$data['project']+=$projectdata
     #   }
      #  else
       # {
        #    $projectdata = @{"fail"="7.14 检查是否已启用需要域控制器身份验证以解锁工作站 1 $config FAIL";}
		#	echo "7.14	检查是否已启需要域控制器身份验证以解锁工作站	可选	建议调整	适用于域环境，此检查项建议调整	1	$config	FAIL		" >> $file_name
		#	$data['project']+=$projectdata
        #}
#7.16 检查是否已禁用“登录时无须按 Ctrl+Alt+Del”策略
$all = $all +1
$Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$Name = 'disablecad'
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
#echo "$config"
   if($config -eq 0)
        {
            $projectdata = @{"true"="7.14 检查是否已禁用登录时无须按Ctrl+Alt+Del 0 $config TRUE";}
			echo "7.14	检查是否已禁用登录时无须按Ctrl+Alt+Del	可选	建议调整	攻击者可能会安装看似标准的登录对话框的特洛伊木马程序，并捕获用户密码。此检查项建议调整	0	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.14 检查是否已禁用登录时无须按Ctrl+Alt+Del 0 $config FAIL";}
			echo "7.14	检查是否已禁用登录时无须按Ctrl+Alt+Del	可选	建议调整	攻击者可能会安装看似标准的登录对话框的特洛伊木马程序，并捕获用户密码。此检查项建议调整	0	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
#7.17 域环境：检查是否已正确配置“可被缓存保存的登录的个数”策略
$all = $all +1
$Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$Name = 'CachedLogonsCount'
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
#echo "$config"
   if($config -le 5)
        {
            $projectdata = @{"true"="7.15 域环境：检查是否已正确配置`可被缓存保存的登录的个数`策略 <=5 $config TRUE";}
			echo "7.15	域环境：检查是否已正确配置`可被缓存保存的登录的个数`策略	可选	建议调整	仅适用于域环境。此检查项建议调整	<=5	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.15 域环境：检查是否已正确配置`可被缓存保存的登录的个数`策略 <=5 $config FAIL";}
			echo "7.15	域环境：检查是否已正确配置`可被缓存保存的登录的个数`策略	可选	建议调整	仅适用于域环境。此检查项建议调整	<=5	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
#7.18 域环境：检查是否已正确配置域环境下安全通道数据的安全设置
echo "7.16	域环境：检查是否已正确配置域环境下安全通道数据的安全设置	可选	建议调整	仅适用于域环境。此检查项建议调整	参考子项	参考子项	参考子项		" >> $file_name
$all = $all +1
#7.18.1 检查是否已启用“域环境下对安全通道数据进行数字加密或数字签名”策略
$Key = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\Netlogon\Parameters'
$Name = 'RequireSignOrSeal'
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
#echo "$config"
   if($config -eq 1)
        {
            $projectdata = @{"true"="7.16.1 检查是否已启`域环境下对安全通道数据进行数字加密或数字签名`策略 1 $config TRUE";}
			echo "7.16.1	检查是否已启`域环境下对安全通道数据进行数字加密或数字签名`策略	可选	建议调整	详情参考父项7.16	1	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.16.1 检查是否已启`域环境下对安全通道数据进行数字加密或数字签名`策略  1 $config FAIL";}
			echo "7.16.1	检查是否已启`域环境下对安全通道数据进行数字加密或数字签名`策略	可选	建议调整	详情参考父项7.16	1	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
#7.18.2 检查是否已启用`域环境下对安全通道数据进行数字签名`策略
$Key = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\Netlogon\Parameters'
$Name = 'SignSecureChannel'
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
#echo "$config"
   if($config -eq 1)
        {
            $projectdata = @{"true"="7.16.2 检查是否已启用`域环境下对安全通道数据进行数字签名`策略 1 $config TRUE";}
			echo "7.16.2	检查是否已启用`域环境下对安全通道数据进行数字签名`策略	可选	建议调整	详情参考父项7.16	1	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.16.2 检查是否已启用`域环境下对安全通道数据进行数字签名`策略 1 $config FAIL";}
			echo "7.16.2	检查是否已启用`域环境下对安全通道数据进行数字签名`策略	可选	建议调整	详情参考父项7.16	1	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }

#7.18.3 检查是否已启用`域环境下对安全通道数据进行数字加密`策略
$Key = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\Netlogon\Parameters'
$Name = 'SealSecureChannel'
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
#echo "$config"
   if($config -eq 1)
        {
            $projectdata = @{"true"="7.17.3 检查是否已启用`域环境下对安全通道数据进行数字加密`策略 1 $config TRUE";}
			echo "7.16.3	检查是否已启用`域环境下对安全通道数据进行数字加密`策略	可选	建议调整	详情参考父项7.16	1	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.17.3 检查是否已启用`域环境下对安全通道数据进行数字加密`策略 1 $config  FAIL";}
			echo "7.16.3	检查是否已启用`域环境下对安全通道数据进行数字加密`策略	可选	建议调整	详情参考父项7.16	1	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }

#7.19 域环境：检查是否已启用`域环境下需要强会话密钥`策略
$all = $all +1
$Key = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\Netlogon\Parameters'
$Name = 'RequireStrongKey'
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
#echo "$config"
   if($config -eq 1)
        {
            $projectdata = @{"true"="7.17 域环境：检查是否已启用`域环境下需要强会话密钥`策略 1 $config TRUE";}
			echo "7.17	域环境：检查是否已启用`域环境下需要强会话密钥`策略	可选	建议调整	仅适用于域环境。此检查项建议调整	1	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.17 域环境：检查是否已启用`域环境下需要强会话密钥`策略 1 $config FAIL";}
			echo "7.17	域环境：检查是否已启用`域环境下需要强会话密钥`策略	可选	建议调整	仅适用于域环境。此检查项建议调整	1	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
#7.20 检查共享文件夹的权限设置是否安全
$all = $all +1
$projectdata = @{"manual"="7.18 检查共享文件夹的权限设置是否安全(请管理员自查)  MANUAL";}
echo "7.18	检查共享文件夹的权限设置是否安全(请管理员自查)	可选	自行判断	共享文件夹权限不该是everyone权限，但此项不适用于域控服务器。此项建议系统管理员根据系统情况自行判断	不等于everyone	null	MANUAL		" >> $file_name
$data['project']+=$projectdata



#7.21 检查是否已启用Windows数据执行保护(DEP)
$all = $all +1
$dep = wmic OS get DataExecutionPrevention_SupportPolicy | findstr "[0-9]"

#echo "$dep"
if ($dep.trim(" ") -eq 2){
	$config = $dep.trim("")
	$projectdata = @{"true"="7.19 检查是否已启用Windows数据执行保护(DEP) 3 $config TRUE";}
	echo "7.19	检查是否已启用Windows数据执行保护(DEP)	可选	自行判断	该基线用以防止代码在未经授权到特定内存区域中运行。此项建议系统管理员根据系统情况自行判断	3	$config	TRUE		" >> $file_name
	
	$data['project']+=$projectdata
}
else{
	$projectdata = @{"fail"="7.19 检查是否已启用Windows数据执行保护(DEP) 3 $config FAIL";}
	echo "7.19	检查是否已启用Windows数据执行保护(DEP)	可选	自行判断	该基线用以防止代码在未经授权到特定内存区域中运行。此项建议系统管理员根据系统情况自行判断	3	$config	FAIL		" >> $file_name
	$data['project']+=$projectdata
}

##7.22 检查是否已创建多个磁盘分区
#$all = $all +1
#$projectdata = @{"manual"="7.21 检查是否已创建多个磁盘分区(请管理员自查)  MANUAL";}
#$data['project']+=$projectdata


#7.23 检查是否已禁止Windows自动登录
$all = $all +1
$flag = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr AutoAdminLogon
#echo "$flag"
if ($flag -ne $null){
	$Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
	$Name = 'AutoAdminLogon'
	$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
	#echo "$config"
		if($config -eq 0)
			{
				$projectdata = @{"true"="7.2 0 检查是否已禁止Windows自动登录 0 $config TRUE";}
				echo "7.2 0	检查是否已禁止Windows自动登录	重要	建议调整	防止非授权访问，服务器应禁止windows自动登录。此检查项建议调整	0	$config	TRUE		" >> $file_name
				$data['project']+=$projectdata
			}
			else
			{
				$projectdata = @{"fail"="7.2 0 检查是否已禁止Windows自动登录 0 $cofnig FAIL";}
				echo "7.2 0	检查是否已禁止Windows自动登录	重要	建议调整	防止非授权访问，服务器应禁止windows自动登录。此检查项建议调整	0	$config	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}

}else{
	$projectdata = @{"manual"="7.2 0 检查是否已禁止Windows自动登录(请管理员自查) 0 $flag MANUAL";}
	echo "7.2 0	检查是否已禁止Windows自动登录	重要	建议调整	防止非授权访问，服务器应禁止windows自动登录。此检查项建议调整	0	$flag	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}


#7.24 检查是否已关闭不必要的服务-Simple TCP/IP Services
$all = $all +1
$sti = get-service | find /c:'Simple TCP/IP' | findstr Running
if($sti -ne $null){
	$projectdata = @{"fail"="7.21 检查是否已关闭不必要的服务-SimpleTCP/IPServices null $sti FAIL";}
	echo "7.21	检查是否已关闭不必要的服务-SimpleTCP/IPServices	重要	建议调整	该协议具有漏洞，如不使用，请关闭该服务。此检查项建议调整	null	$sti	FAIL		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"true"="7.21 检查是否已关闭不必要的服务-SimpleTCP/IPServices null $sti TRUE";}
	echo "7.21	检查是否已关闭不必要的服务-SimpleTCP/IPServices	重要	建议调整	该协议具有漏洞，如不使用，请关闭该服务。此检查项建议调整	null	$sti	TRUE		" >> $file_name
	$data['project']+=$projectdata
}


#7.25 检查是否已关闭不必要的服务-Simple Mail Transport Protocol (SMTP)
$all = $all +1
$sti = get-service | find /c:'Simple Mail Transport Protocol (SMTP)' | findstr Running
if($sti -ne $null){
	$projectdata = @{"fail"="7.22 检查是否已关闭不必要的服务-SimpleMailTransportProtocol(SMTP) null $sti FAIL";}
	echo "7.22	检查是否已关闭不必要的服务-SimpleMailTransportProtocol(SMTP)	重要	建议调整	该协议常被用来邮箱伪造、钓鱼攻击，请关闭该服务。此检查项建议调整	null	$sti	FAIL		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"true"="7.22 检查是否已关闭不必要的服务-SimpleMailTransportProtocol(SMTP) null $sti TRUE";}
	echo "7.22	检查是否已关闭不必要的服务-SimpleMailTransportProtocol(SMTP)	重要	建议调整	该协议常被用来邮箱伪造、钓鱼攻击，请关闭该服务。此检查项建议调整	null	$sti	TRUE		" >> $file_name
	$data['project']+=$projectdata
}


#7.26 检查是否已关闭不必要的服务-Windows Internet Name Service (WINS)
$all = $all +1
$sti = get-service | find /c:'Windows Internet Name Service (WINS)' | findstr Running
if($sti -ne $null){
	$projectdata = @{"fail"="7.23 检查是否已关闭不必要的服务-WindowsInternetNameService(WINS) null $sti FAIL";}
	echo "7.23	检查是否已关闭不必要的服务-WindowsInternetNameService(WINS)	重要	建议调整	该协议可能存在远程代码执行漏洞，如不使用，请关闭该服务。此检查项建议调整	null	$sti	FAIL		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"true"="7.23 检查是否已关闭不必要的服务-WindowsInternetNameService(WINS) null $sti TRUE";}
	echo "7.23	检查是否已关闭不必要的服务-WindowsInternetNameService(WINS)	重要	建议调整	该协议可能存在远程代码执行漏洞，如不使用，请关闭该服务。此检查项建议调整	null	$sti	TRUE		" >> $file_name
	$data['project']+=$projectdata
}


#7.27 检查是否已关闭不必要的服务-DHCP Server
$all = $all +1
$sti = get-service | find /c:'DHCP Server' | findstr Running
if($sti -ne $null){
	$projectdata = @{"fail"="7.24 检查是否已关闭不必要的服务-DHCPServer null $sti FAIL";}
	echo "7.24	检查是否已关闭不必要的服务-DHCPServer	重要	建议调整	该协议具有一些安全问题，如DHCP欺骗攻击，如不使用，请关闭该服务。此检查项建议调整	null	$sti	FAIL		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"true"="7.24 检查是否已关闭不必要的服务-DHCPServer null $sti TRUE";}
	echo "7.24	检查是否已关闭不必要的服务-DHCPServer	重要	建议调整	该协议具有一些安全问题，如DHCP欺骗攻击，如不使用，请关闭该服务。此检查项建议调整	null	$sti	TRUE		" >> $file_name
	$data['project']+=$projectdata
}


##7.28 检查是否已关闭不必要的服务-Remote Access Connection Manager
#$all = $all +1
#$sti = get-service | find /c:'Remote Access Connection Manager' | findstr Running
#if($sti -ne $null){
#	$projectdata = @{"fail"="7.28 检查是否已关闭不必要的服务-RemoteAccessConnectionManager  FAIL";}
#	$data['project']+=$projectdata
#}else{
#	$projectdata = @{"true"="7.28 检查是否已关闭不必要的服务-RemoteAccessConnectionManager  TRUE";}
#	$data['project']+=$projectdata
#}


#7.29 检查是否已关闭不必要的服务-Message Queuing
$all = $all +1

$sti = get-service | find /c:'Message Queuing' | findstr Running
if($sti -ne $null){
	$projectdata = @{"fail"="7.25 检查是否已关闭不必要的服务-MessageQueuing null $sti FAIL";}
	echo "7.25	检查是否已关闭不必要的服务-MessageQueuing	重要	建议调整	该服务在MSMQ中存在权限提升漏洞，如不使用，请关闭该服务。此检查项建议调整	null	$sti	FAIL		" >> $file_name
	
	$data['project']+=$projectdata
}else{
	$projectdata = @{"true"="7.25 检查是否已关闭不必要的服务-MessageQueuing null $sti TRUE";}
	echo "7.25	检查是否已关闭不必要的服务-MessageQueuing	重要	建议调整	该服务在MSMQ中存在权限提升漏洞，如不使用，请关闭该服务。此检查项建议调整	null	$sti	TRUE		" >> $file_name
	$data['project']+=$projectdata
}


#获取当前运行脚本的时间
$date = Get-Date
$date
#将当前时间写入txt
#$date >>windowsResult.txt

#循环遍历data.project
#true------配置正常
#fail------配置错误
echo "序号 基线名称 标准值 检查情况 符合性"
echo ""
foreach ($i in $data.project){

	if ($($i.true) -ne $null){
		echo "$($i.true)"
		echo ""
		#echo "_________________________________________________________________________|"
		#$i.true >>$file_name
		$t = $t + 1
	}
	if  ($($i.fail) -ne $null){
		echo "$($i.fail)"
		echo ""
		#$i.fail >>$file_name
		$f = $f + 1

	}
	if ($($i.manual) -ne $null){
		echo "$($i.manual)"

		echo ""
		#$i.manual >>$file_name
		$m = $m + 1
	}

}

$allin = $t + $f + $m

echo "扫描时间: $date" >> $file_name
echo "检查基线条目: $all" >> $file_name
echo "检查全部基线条目: $allin " >> $file_name
echo "检查符合基线条目: $t" >> $file_name
echo "检查不符基线条目: $f" >> $file_name
echo "检查手工基线条目: $m" >> $file_name





echo "	 ____________________________"

echo "	| 检查基线条目：    |   $all   |"
echo "	|___________________|________|"

echo "	| 检查全部基线条目：|   $allin   |----->说明：全部基线条目为检查父项和子项相加得到"
echo "	|___________________|________|"

echo "	| 检查符合基线条目：|   $t   |"
echo "	|___________________|________|"

echo "	| 检查不符基线条目：|   $f   |"
echo "	|___________________|________|"

echo "	| 检查手工基线条目：|   $m   |"
echo "	|___________________|________|"



