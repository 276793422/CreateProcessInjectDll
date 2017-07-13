# CreateProcessInjectDll
创建进程之后，向进程内部注入一个DLL。
此工程实际上是一个UT的Shell 部分。
我的本质需求是做一个UT框架，
框架要求创建一个子进程，然后向子进程中注入一个DLL ，
这个DLL来做一系列的事情，为后续测试做前置工作。
此工具的原理：挂起创建进程，
获取进程信息（镜像信息，EP信息等等），
HOOK 修改EP ，跳转到一段ShellCode ，
ShellCode 修复 EP 然后做简单的LoadLibrary 操作，
这时DLL 就在LoadLibrary 里面执行了，
DLL 执行之后，跳回原来的位置。
逻辑上非常简单。代码量也很少，一共连调带写，就几个小时就完事了。
目前不足：只支持x86 子进程，不支持x64 注入，
想支持，其实不难，但是需要写x64 的ShellCode ，我没这个需求。