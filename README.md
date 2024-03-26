# windows&Linux基线检查配置文档和自动化脚本
windows和linux基线检查，配套自动化检查脚本。纯手工编写。

基线配置文档：
      本文规定了LINUX操作系统主机应当遵循的操作系统安全性设置标准，本文档旨在指导系统管理人员或安全检查人员进行LINUX 操作系统的安全合规性检查和配置。
服务器安全基线是指为满足安全规范要求，考虑到信息安全管理的三+四个特性：保密性、完整性、可用性、可审计性、可靠性、抗抵赖性。服务器安全配置必须达到的标准，一般通过检查安全配置参数是否符合安全标准或公司标准来度量。主要包括了账号配置安全、口令配置安全、授权配置、日志配置、IP通信配置等方面内容，这些安全配置直接反映了系统自身的安全脆弱性。  
        ![image](https://user-images.githubusercontent.com/40255379/142581629-c879b9ae-ce15-45eb-af93-fbcaa588fef7.png)

windows脚本：
    使用powershell运行.\windowsCheck2.1.ps1，运行报错解决![image](https://user-images.githubusercontent.com/40255379/142582487-bdc92c8b-8215-43b9-b438-e7be41bb4003.png)
        
   powershell输入set-ExecutionPolicy Unrestricted  键入：Y![image](https://user-images.githubusercontent.com/40255379/142583004-b7c9ce7d-5254-4e48-b792-17e93cfde0ce.png)
        
   运行截图![image](https://user-images.githubusercontent.com/40255379/142583521-c576c998-62c3-4c49-9a23-05422bb679ce.png)
       
   运行完成后生成ip.csv文件![image](https://user-images.githubusercontent.com/40255379/142583685-7fa5c15f-3572-4ec4-82e7-eea58971c5c2.png)
       
   注意： 当使用excel2007 打开生成的csv文件时，如果出现乱码情况，请调整脚本的编码类型：
 脚本第七行：#$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'  --->$PSDefaultParameterValues['Out-File:Encoding'] = 'oem'
 再次运行即可。感谢https://github.com/softzcw 大佬指出该问题！！


Linux脚本：
       ./linuxcheck2.2.sh![image](https://user-images.githubusercontent.com/40255379/142585459-63be1daa-377b-48ff-9f8e-1f6247cfbc05.png)。
       ..
      运行完成后生成checklist.csv文件
![image](https://user-images.githubusercontent.com/40255379/142585896-464f8927-352e-4d3b-a8ea-1381d313502e.png)。
为了更加方便阅读，请对其进行分列，按照tab键进行分列。



                                                                                                      BY：唐杰
                                                                                                      2021年11月19号
  
