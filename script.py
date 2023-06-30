##################################################################################################################
# Windows process killer, spawner, and access token privilege manipulator                                        #
# Callum Leonard                                                                                                 #
##################################################################################################################
# [+] All Direct References Required To Build The Script: -                                                      #
# Structures:                                                                                                    #
# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_luid_and_attributes                 #
# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges                            #
# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-privilege_set                               #
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa        #
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information #
#----------------------------------------------------------------------------------------------------------------#
# Miscellaneous:                                                                                                 #
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess         #
# https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants                                   #
# https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights                  #
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess    #
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken    #
# https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights                  #
# https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-privilegecheck          #
# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_luid_and_attributes                 #
# https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-                               #
# https://learn.microsoft.com/en-us/windows/win32/learnwin32/working-with-strings                                #
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw      # 
# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/igpupvdev/ns-igpupvdev-_luid                    #
# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-privilege_set                               #
# https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew                   #
# https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror              #
# https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew                   #
# https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges   #
# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges                            #
# https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags                              #
# https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects                #
#----------------------------------------------------------------------------------------------------------------#
# SE PRIV ENABLED:                                                                                               #
# https://referencesource.microsoft.com/#system/compmod/microsoft/win32/NativeMethods.cs,98ce25e56b86729e        #
# WINTYPES -> CTYPES Conversion:                                                                                 #
# https://epydoc.sourceforge.net/stdlib/ctypes.wintypes-module.html                                              #
##################################################################################################################

#ctypes, allows us to interface directly with Windows .dll's
import ctypes
import argparse
import re
from time import sleep

#Function def for destroying or restoring privileges
#Taking in parameter "lpWindowArg" which contains the application to destroy
def alterPrivs(lpWindowArg):
   
    #LUID Struct
    class LUID(ctypes.Structure):
        _fields_ = [
        ("LowPart", ctypes.c_ulong),
        ("HighPart", ctypes.c_ulong),
        ]
        
    #LUID_AND_ATTRIBUTES struct, see Windows ref
    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
        ("Luid", LUID),
        ("Attributes", ctypes.c_ulong),
        ]
    
    #Our token privileges struct, see Windows ref
    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
        ("PrivilegeCount", ctypes.c_ulong),
        ("Privilege", LUID_AND_ATTRIBUTES),
        ]
    
    #Privilege set struct, see Windows ref
    class PRIVILEGE_SET(ctypes.Structure):
        _fields_ = [
        ("PrivilegeCount", ctypes.c_ulong),
        ("Control", ctypes.c_ulong),
        ("Privilege", LUID_AND_ATTRIBUTES),
        ]

    #Defining token access parameters, see Windows ref
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    STANDARD_RIGHTS_READ = 0x00020000
    TOKEN_ASSIGN_PRIMARY = 0x0001
    TOKEN_DUPLICATE = 0x0002
    TOKEN_IMPERSONATION = 0x0004
    TOKEN_QUERY = 0x0008
    TOKEN_QUERY_SOURCE = 0x0010
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_ADJUST_GROUPS = 0x0040
    TOKEN_ADJUST_DEFAULT = 0x0080
    TOKEN_ADJUST_SESSIONID = 0x0100
    TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
    TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
                        TOKEN_ASSIGN_PRIMARY     |
                        TOKEN_DUPLICATE          |
                        TOKEN_IMPERSONATION      |
                        TOKEN_QUERY              |
                        TOKEN_QUERY_SOURCE       |
                        TOKEN_ADJUST_PRIVILEGES  |
                        TOKEN_ADJUST_GROUPS      |
                        TOKEN_ADJUST_DEFAULT     |
                        TOKEN_ADJUST_SESSIONID)
                        

    #Creating a handle to directly interface with the User32.dll
    user_handle = ctypes.WinDLL("User32.dll")
    #Getting user input for later script functionality, storing it in a variable
    priv_choice = int(input("Press 1 to destroy process token privilages or 2 to restore process token privilages: "))
    
    #API call to obtain a Window handle to the specificed process
    lpClassName = None
    findWindowAPI_resp = user_handle.FindWindowA(lpClassName, lpWindowArg)

    #Our handle to directly interface with the Kernel32.dll
    kernel_handle = ctypes.WinDLL("Kernel32.dll")
    get_error = kernel_handle.GetLastError()

    #Windows documentation informs that API call response of 0 indcates a failure
    #Implementing appropriate erorr checking with the kernel get last error func
    if findWindowAPI_resp == 0:
        sleep(0.25)
        print("[-] Could Not Obtain Handle. Error code: {0}".format(get_error))
        exit(1)
    else:
        print("\n[+] Successfully Obtained Handle To Process")
        sleep(0.25)

    #Pointer to var that receives process id
    getID = ctypes.c_ulong()
    #API call to obtain thread ID that created initial window, passing in the handle and the pointer
    #Passing the pointer byref as required by the documentation
    procAPI_resp = user_handle.GetWindowThreadProcessId(findWindowAPI_resp, ctypes.byref(getID))

    #Windows documentation informs that API call response of 0 indcates a failure
    #Implementing appropriate erorr checking with the kernel get last error function
    if procAPI_resp == 0:
        sleep(0.25)
        print("[-] Could Not Obtain Process ID. Error code: {0}".format(get_error))
        exit(1)
    else:
        print("[+] Successfully Obtained Process ID")
        sleep(0.25)
        
    #Grants all access rights for process object, see Windows ref
    PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
    #Opening process via process ID with the defined access rights
    dwDesiredAccess = PROCESS_ALL_ACCESS
    dwProcessId = getID
    bInheritHandle = False
    
    #Issuing the API call to open the specificed process
    procAPI_resp = kernel_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    #Saving the process ID inside var p_ID
    p_ID = str(getID)
    #Regex to strip unncessary chars, display only the relevant process id
    p_ID = re.sub('[^0-9]','', p_ID)
    #Windows documentation informs that API call response of 0 indcates a failure
    #Implementing appropriate erorr checking with the kernel get last error func
    if procAPI_resp == 0:
        sleep(0.25)
        print("[-] Could Not Open Specified Process. Error code: {0}".format(get_error))
        exit(1)
    else:
        print("[+] Successfully Opened Process ID: " + p_ID)
        sleep(0.25)

    #Making a handle to the advanced funtionality dll, allows us to use API calls relating to token lookups and modifications
    adv_handle = ctypes.WinDLL("Advapi32.dll")
    
    #Creating a Privileged handle, used to modify tokens privs etc
    #Opening handle to specificed processes token
    hProcess = procAPI_resp
    ProcessHandle = hProcess
    TokenHandle = ctypes.c_void_p()
    DesiredAccess = TOKEN_ALL_ACCESS
    
    #Issuing the API call to obtain the processes access token
    opnProc_resp = adv_handle.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))
    #Relevent error checking as described by the API call return documentation
    if opnProc_resp != 0:
        sleep(0.25)
        print("[+] Handle To Process Access Token Succesfully Opened \n")
        sleep(0.25)
    else:
        print("[-] Failed To Open Handle To Process Access Token. Error code: {0}".format(kernel_handle.GetLastError()))
        exit(1)
        sleep(0.25)

    #Creating a privileges set for necessary call later
    clientToken = TokenHandle
    requiredPrivileges = PRIVILEGE_SET() 
    requiredPrivileges.PrivilegeCount = 1 #Only 1 privilege to be worked with at a time
    requiredPrivileges.Privilege = LUID_AND_ATTRIBUTES() #Create new LUID_AND_ATTRIBUTES
    requiredPrivileges.Privilege.Luid = LUID() #Creating new LUID inside of LUID_AND_ATTRIBUTES struct
    lpLuid = requiredPrivileges.Privilege.Luid
    
    #Pointer to PrivilegeCheck func, indicates whether specificed priv is enabled by returning true
    pfResult = ctypes.c_long()
   
    #List of majority of Window token privileges, used later for making API call
    priv_list = ["SEDebugPrivilege", "SECreateSymbolicLinkPrivilege", "SEImpersonatePrivilege", 
    "InvalidPrivilegeTest", "SERestorePrivilege", "SEShutdownPrivilege", "Thisisinvalid",
    "SETimeZonePrivilege", "SEBackupPrivilege", "SEChangeNotifyPrivilege", "SECreateGlobalPrivilege",
    "SECreatePagefilePrivilege", "SEDelegateSessionUserImpersonatePrivilege", "SESecurityPrivilege",
    "SETakeOwnershipPrivilege", "SEIncreaseWorkingSetPrivilege", "SESystemProfilePrivilege", "SERemoteShutdownPrivilege", 
    "SESystemtimePrivilege", "SEInvalidPriv", "SEUndockPrivilege", "SESystemEnviromentPrivilege", "SEProfileSingleProcessPrivilege", 
    "SEManageVolumePrivilege", "SELoadDriverPrivilege"]
    
    #Empty list to store valid privileges used to specificed process
    valid_privs = []
    
    #Empty list to store privileges that are rejected/invalid
    rejected_privs = []

    #Iterate from 0 to the length of the list, 1 iteration for each privilege
    for x in range(len(priv_list)):
        
        #API call parameter
        lpSystemName = None
        
        #Store the current list privilege inside lpName
        #With each iteration update API call param with a new privilege
        lpName = priv_list[x]
        
        #Setup necessary error checking
        catch_error = kernel_handle.GetLastError()
        
        #Issue API call to obtain value of specificed privilege and configure the previously defined LUID
        lkPriv_resp = adv_handle.LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(lpLuid))

        #Lets us know if LUID retrivals worked
        if lkPriv_resp != 0:
            print("[+] LUID Successfully Retrieved")
            sleep(0.25)

        #Condition to assess whether returned LUID is valid. LUID highpart and lowpart will both be 0 if specificed privilege is not valid
        #Tells us how many of the privileges defined in the list are valid or apply to the current process
        elif lpLuid.HighPart == 0 and lpLuid.LowPart == 0:
                print("[+] LUID Successfully Retrieved \n[-] Privilege: " + lpName + " is not a valid privilege associated with this process \n")
                rejected_privs.append(lpName)
                #if this is the case we don't want to add this privilege -
                #to the valid privilege list "list3" or make further API calls below, so force next iteration of next privilege now
                del lpName
                continue
        
        #Error checking
        elif response == 0:
                print("[-] Could Not Obtain LUID. Error code: {0}".format(catch_error))

        #API call to check whether valid privilege is disabled or enabled in the process access token
        privCk_resp = adv_handle.PrivilegeCheck(clientToken, ctypes.byref(requiredPrivileges), ctypes.byref(pfResult))

        #If function successful 0 is returned
        if privCk_resp != 0:
            print("[*] Running Privilege Checks On Process...")
      
            sleep(1.50)
        else:
             print("[-] Could Not Run Privilege Check on Process. Error code: {0}".format(catch_error))
         
        #Windows predefined value to enable a specificed privilege
        SE_PRIVILEGE_ENABLED = 2
      
        #Based on user input do...
        #if the pfResult pointer returns true we know that the privilege is enabled
        if priv_choice == 1 and pfResult:
            
            #lpName displays the current privilege in question
            print("[!] Privilege: {0}".format(lpName) + " is Enabled")
            print("[!] Destroying Enabled Privilege [!]\n")
            #we know the privilege is enabled, disable the current list3 priv
            requiredPrivileges.Privilege.Attributes = 0
            sleep(1)
        
        #Based on user input do...
        #If the pfResult pointer returns false but the choice is still 1 disable all privs anyway
        elif priv_choice == 1 and not pfResult:
            print("[!] Privilege: {0}".format(lpName) + " Is Valid, However Appears To Be Already Destroyed Or Is Not Used By This Process, Confirming...")
            print("[*] Confirmed [*] \n")
            #still disable regardless
            requiredPrivileges.Privilege.Attributes = 0
            sleep(0.35)
        
        #Based on user input do...
        #If choice is to enable then we make sure that the priv pointer is currently returning false (disabled)
        elif priv_choice == 2 and not pfResult:
            print("[!] Privilege: {0}".format(lpName) + " is Destroyed")
            print("[!] Restoring Destroyed Privilege [!]\n")
            #enable the current priv
            requiredPrivileges.Privilege.Attributes = SE_PRIVILEGE_ENABLED
         
        #Based on user input do...
        #If the choice is to enable but the specificed priv is already enabled display appropriate message
        elif priv_choice == 2 and pfResult:
            print("[!] Privilege: {0}".format(lpName) + " Is Valid, However Appears To Be Already Enabled Or Is Not Used By This Process, Confirming...")
            print("[*] Confirmed [*] \n")
            #still enable the priv regardless
            requiredPrivileges.Privilege.Attributes = SE_PRIVILEGE_ENABLED
        
        #Invalid option, let the program know something went wrong
        else:
            print("Invalid choice, exiting...")
            sleep(0.30)
            exit(1)
            
        #Setup necessary params for token privilege modification (enable, disable)
        DisableAllPrivileges = False
        NewState = TOKEN_PRIVILEGES()
        BufferLength = ctypes.sizeof(NewState)
        PreviousState = ctypes.c_void_p()
        ReturnLength = ctypes.c_void_p()
        NewState.Privilege = requiredPrivileges.Privilege
        NewState.PrivilegeCount = 1
        
        TokenHandle = clientToken
        #Issue API call to adjust the current token privileges for the specificed process 
        adjTkn_resp = adv_handle.AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, ctypes.byref(NewState), BufferLength, ctypes.byref(PreviousState), ctypes.byref(ReturnLength))
        #Add the privilege that we have been dealing with into the new valid privilege list
        valid_privs.append(lpName)
        #Delete the current privilege variable, next for loop iteration initates the new privilege within the list
        del lpName
    
    #Issue this condition outside of for loop, if the user choice to destroy privs then...
    if priv_choice == 1:
        print("[+] The following process-associated token privileges were either destroyed or are valid Windows privileges \n")
        print(*valid_privs,sep='\n')
        
        print("\n[+] The following token privileges were invalid \n")
        print(*rejected_privs,sep='\n')
    
    #Issue this condition outside of for loop, if the user choice to destroy privs then...
    elif priv_choice == 2:
        print("\n[+] The following process-associated token privileges were either restored or are valid Windows privileges \n")
        print(*valid_privs,sep='\n')
    
        print("\n[+] The following token privileges were invalid \n")
        print(*rejected_privs,sep='\n')
    
    #Make a handle to the Kernel32 dll for error checking
    adjtkn_error = ctypes.WinDLL("Kernel32.dll")
    #Test if our token adjustment API call was successful, if not dispaly the erorr code
    if adjTkn_resp != 0:
        print("\n[+] All Token Privilege Modifications Successful [+]")
    else:
        print("[-] Token Privilege Modifications Unsuccessful. Error code: {0}".format(adjtkn_error))
    
#Function def for killing a Windows Process
#Takes in 1 argument, the arugument being the process to kill    
def killProc(lpWindowArg):
    #Our user handle to interface with User32.dll
    user_handle = ctypes.WinDLL("User32.dll")
    
    #Parameter intilisation and API call to obtain a Window handle to the specificed process
    lpClassName = None
    window_handle = user_handle.FindWindowA(lpClassName, lpWindowArg)

    #Implement error checking by handling kernel32
    kernel_handle = ctypes.WinDLL("Kernel32.dll")
    catch_error = kernel_handle.GetLastError()

    #We know from the windows error documentation that anything over 0 is an error codee
    if window_handle == 0:
        sleep(0.75)
        print("[-] Could Not Obtain Handle. Error code: {0}".format(catch_error))
        exit(1)
    else:
        print("\n[+] Successfully Obtained Handle To Process")
        sleep(0.75)
  
    #Pointer to var that receives process id
    getID = ctypes.c_ulong()
    
    #API call to obtain thread ID that created initial window, passing in the handle and the pointer
    #Passing the pointer byref as required by the documentation
    procID_resp = user_handle.GetWindowThreadProcessId(window_handle, ctypes.byref(getID))

    if procID_resp == 0:
        sleep(0.75)
        print("[-] Could Not Obtain Process ID. Error code: {0}".format(catch_error))
        exit(1)
    else:
        print("[+] Successfully Obtained Process ID")
        sleep(0.75)
    
    #Grants all access rights for process object
    PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
    #Opening process via process ID with the defined access rights
    dwDesiredAccess = PROCESS_ALL_ACCESS
    bInheritHandle = False
    dwProcessId = getID

    #Issuing the API call to open the specificed process
    opnProc_resp = kernel_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    #Saving the process ID inside var p_ID
    p_ID = str(getID)
    #Regex to strip unncessary chars, display only the relevant process id
    p_ID = re.sub('[^0-9]','', p_ID)
    #Appropaite error checking for opnPROC API call response, we know from documentation 0 is an error
    error = kernel_handle.GetLastError()
    if opnProc_resp == 0:
        sleep(0.75)
        print("[-] Could Not Open Specified Process. Error code: {0}".format(error))
        exit(1)
    else:
        print("[+] Successfully Opened Process ID: " + p_ID)
        sleep(0.75)
        
    #Parameters to launch API call, handle to specificed process and generic exitcode value  
    hProcess = opnProc_resp
    uExitcode = ctypes.c_ulong(0)
    #API call to terminate the specificed process and all of its associated threads
    term_proc = kernel_handle.TerminateProcess(opnProc_resp, uExitcode)
    #Appropaite error checking based on API call response
    if term_proc !=0:
        sleep(0.45)
        print("[*] Process Successfully Killed")
    else:
        sleep(0.75)
        print("[-] Could Not Terminate Process. Error code: {0}".format(error))

#function def for spawning a process
#Takes in 1 parameter which contains the application to spawn
def spawnProc(lpApplicationName):
    #STARTUPINFOA struct, see windows ref
    class STARTUPINFOA(ctypes.Structure):
        _fields_ = [
        ("cb", ctypes.c_ulong),
        ("lpReserved", ctypes.c_char_p),
        ("lpDesktop", ctypes.c_char_p), 
        ("lpTitle", ctypes.c_char_p), 
        ("dwX", ctypes.c_ulong),
        ("dwY", ctypes.c_ulong),
        ("dwXSize", ctypes.c_ulong),
        ("dwYSize", ctypes.c_ulong),
        ("dwXCountChars", ctypes.c_ulong),
        ("dwYCountChars", ctypes.c_ulong),
        ("dwFillAttribute", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("wShowWindow", ctypes.c_ushort),
        ("cbReserved2", ctypes.c_ushort),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", ctypes.c_void_p),
        ("hStdOutput", ctypes.c_void_p),
        ("hStdError", ctypes.c_void_p),
        ]
    #PROCESS_INFORMATION struct, see windows ref    
    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", ctypes.c_void_p),
            ("hThread", ctypes.c_void_p),
            ("dwProcessId", ctypes.c_ulong),
            ("dwThreadId", ctypes.c_ulong),
            ]

    #Our kernel handle to interface with Kernel32.dll
    kernel_handle = ctypes.WinDLL("Kernel32.dll")
    
    #Specifying our directory path and concatinating the user supplied input onto the end providing an 
    #absolute path to the application to run
    userProgram = lpApplicationName
    lpApplicationName = "C:\\Windows\\System32\\" + userProgram
    lpCommandLine = None
    lpProcessAttributes = None
    lpThreadAttributes = None
    lpEnviroment = None
    lpCurrentDirectory = None
    bInheritHandles = False
    #Process creation flag, specific value instructs the new process to open in a new window/console
    #instead of inheriting parent
    dwCreationFlags = 0x00000010

    #Pointer to the process information structure as required by Windows ref
    #Receives ID info about the new process spawned
    lpProcessInformation = PROCESS_INFORMATION()
    #Pointer to the startup info structure
    #Ensures the standard handle fields in STARTUPINFO struct contain valid handle values
    lpStartupInfo = STARTUPINFOA()

    lpStartupInfo.wShowWindow = 0x1
    #Determines whether STARTUPINFO struct members are used when the process, creates a new window
    lpStartupInfo.dwFlags = 0x1
    sleep(0.25)
    
    #API call to create a new process and its associated primary thread, takes in all previously mentioned parameters
    crProc_return = kernel_handle.CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,dwCreationFlags, lpEnviroment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    #Appropaite error handling, success is any value except 0
    error = kernel_handle.GetLastError()
    if crProc_return != 0:
        sleep(0.45)
        print("\n[+] Successfully Spawned: " + userProgram)
        sleep(0.50)
        print("[+] Creating New Window For: " + userProgram)
        sleep(0.65)
    else:
        print("Error Could Not Spawn Program. Error code: {0}".format(error))
        
#Function def for capturing arguments       
def args():

    #Define our argument parser and add individual arguments to be processed
    parser = argparse.ArgumentParser(description='Use this script to spawn and kill Windows processes.\nThis script may also be used to destroy and restore process privilages.')
    all_args = parser.add_argument_group('All arguments')
    all_args.add_argument("-s", help="The application to spawn | Usage: py script.py -s cmd.exe", required=False)
    all_args.add_argument("-k", help="The current running application to kill | Usage: py script.py -k \"Task Manager\" ", required=False)
    all_args.add_argument("-p", help="Enable and Disable all Windows token privileges for the specificed application | Usage: py script.py -p \"Command Prompt\" ", required=False)
    
    args = parser.parse_args()
    #Setting the value contained within each argument to a recognisable variable name
    spawn = args.s
    kill = args.k
    en_dis = args.p
    
    #Performing error checking if no parameters are detected
    if args.s == None and args.k == None and args.p == None:
        sleep(0.35)
        print("\n[-] Error: Script must take 1 argument \n[-] Script Usage: -h for help")
        exit(1)
        
    #If no argument is selected the value is none, however a selected arg will store the input
    #Running a specific function based on if the argument -s was chosen
    elif args.s != None and args.k == None and args.p == None:
        lpApplicationName = str(spawn)
        spawnProc(lpApplicationName)
    
    #Running a specific function based on if the argument -k was chosen
    elif args.k != None and args.s == None and args.p == None:
        #The API call which uses the WindowName must be a pointer to a string and be utf-8 encoded
        lpWindowName = ctypes.c_char_p(kill.encode('utf-8'))
        killProc(lpWindowName)
    
    #Running a specific function based on if the argument -p was chosen
    elif args.p != None and args.s == None and args.k == None:
        #The API call which uses the WindowName must be a pointer to a string and be utf-8 encoded
        lpWindowName2 = ctypes.c_char_p(en_dis.encode('utf-8'))
        alterPrivs(lpWindowName2)
    else:   
        print("\n[-] Error: Script must only take 1 argument \n[-] Script Usage: -h for help")
        exit(1)
args()