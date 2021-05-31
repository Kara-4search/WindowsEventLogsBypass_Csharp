# WindowsEventLogsBypass_Csharp

Blog link: working on it
* Bypass **windows eventlogs** & **Sysmon,only** tested in win10_x64.

* Only for red team purpose, and you need to change the codes if u use it for pentest.
* You need **administrator privilege** to run it.
* You also need **administrator privilege** to debug or test the code(In VS).
* Feel free to make any issues or advice.



Process Explorer

![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/Screen%20Shot%202021-05-31%20at%205.05.31%20PM.png)



![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/Screen%20Shot%202021-05-31%20at%205.22.34%20PM.png)





## Reference link

1. https://www.pinvoke.net/search.aspx?search=NtWriteVirtualMemory&namespace=[All]
2. https://wj32.org/wp/2010/03/30/howto-use-i_querytaginformation/
3. https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/SuspendorResumeTidEx.cpp
4. https://0cch.com/2015/01/24/e794a8service-tage58cbae58886e585b1e4baabe7b1bbe59e8be69c8de58aa1e7babfe7a88b/
5. https://artofpwn.com/2017/06/05/phant0m-killing-windows-event-log.html
6. https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads
7. https://blog.csdn.net/singleyellow/article/details/93394557
8. https://github.com/3gstudent/Windows-EventLog-Bypass/blob/master/WindowsEventLogBypass.cpp
9. https://www.pinvoke.net/default.aspx/advapi32.adjusttokenprivileges

1. https://www.cnblogs.com/DeeLMind/p/7194102.html
2. https://www.pinvoke.net/default.aspx/kernel32/SuspendThread.html