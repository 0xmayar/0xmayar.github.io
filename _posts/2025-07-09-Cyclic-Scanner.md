---
title: Cyclic Scanner - MHL
date: 2025-07-09 01:00:00 +0200
categories: [Mobile Hacking Lab, Android]
tags: [Android , service , RCE , static-analysis]
toc: true
comments: true
image: ./assets/img/attachments/cyclic-4.png
imageNameKey: cyclic
---
Hey Everyone!
Today we are digging in this challenge from Mobile Hacking Lab. This lab is designed to mimic real-world scenarios where vulnerabilities within Android services lead to exploitable situations.
Note: its required to use android 11+, I was using LDplayer and the app crashed so using NOX with android 11 was the solution to it.
` android:compileSdkVersion="34"`
## First Steps into App Functionality
When I run the app at first, it requests a permission to all file access, without it the app won't work
![](/assets/img/attachments/attachemnts/cyclic.png)

After granting it this permission, we see this toggle switch
![](/assets/img/attachments/attachemnts/cyclic.png)
and the message we get if we tried to turn it off, so lets start analyzing the code and understand what we have here!
## Manifest File Analysis
```xml
    android:versionCode="1"
  
    android:versionName="1.0"
  
    android:compileSdkVersion="34"
  
    android:compileSdkVersionCodename="14"
  
    package="com.mobilehackinglab.cyclicscanner"
  
    platformBuildVersionCode="34"
  
    platformBuildVersionName="14"
  
    <uses-sdk
  
        android:minSdkVersion="30"
  
        android:targetSdkVersion="33"/>
```
First thing in the code as we mentioned before is the Android version compatibility. The app requires a minimum Android SDK version of 30 (Android 11). This means the app is designed to run on Android 11 and above, and is optimized for Android 13 behavior.
```xml
 <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
  
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
  
    <uses-permission android:name="android.permission.INTERNET"/>
  
    <permission
  
        android:name="com.mobilehackinglab.cyclicscanner.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
  
        android:protectionLevel="signature"/>
  
    <uses-permission android:name="com.mobilehackinglab.cyclicscanner.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
```
Here, we can see **Four permissions** declared in the manifest, including one **custom permission**.

- `**MANAGE_EXTERNAL_STORAGE**`: As observed when launching the app, it requests full access to external storage (sdcard). This permission provides broader access than the typical `READ_EXTERNAL_STORAGE` or `WRITE_EXTERNAL_STORAGE` permissions, allowing the app to manage all files on shared storage.
    
- `**FOREGROUND_SERVICE**`: This is required for running background tasks in the form of a **foreground service**, which we'll see later. Foreground services must declare this permission to function properly in recent Android versions.
```xml
<activity
  
            android:name="com.mobilehackinglab.cyclicscanner.MainActivity"
  
            android:exported="true">
  
            <intent-filter>
  
                <action android:name="android.intent.action.MAIN"/>
  
                <category android:name="android.intent.category.LAUNCHER"/>
  
            </intent-filter>
  
        </activity>
  
        <service
  
            android:name="com.mobilehackinglab.cyclicscanner.scanner.ScanService"
  
            android:exported="false"/>
```
Finally, we see the declaration of the app's main components in the manifest:
- **`MainActivity`**: This is the main entry point of the application, defined with the appropriate intent filter to launch when the app starts.
    
- **`ScanService`**: This is the foreground service used by the app to perform background scanning tasks

The remaining components in the manifest are related to **AndroidX libraries**, such as **emoji compatibility**, **lifecycle management**, and **profile installation**.

## ScanService Class Analysis 
```java
 private static final String CHANNEL_ID = "ForegroundScanServiceChannel";
  
    private static final String CHANNEL_NAME = "ScanService";
  
    private static final long SCAN_INTERVAL = 6000;
  
    private ServiceHandler serviceHandler;
  
    private Looper serviceLooper;
```
**CHANNEL_ID** and **CHANNEL_NAME** are used to configure the notification channel required for foreground services on Android 8.0 and above.
**SCAN_INTERVAL** is set to 6000 milliseconds (6 seconds), which represents the delay between each scan cycle.>)

The `ScanService` class also includes the `**onCreate()**`, `**onStartCommand()**`, and `**createNotificationChannel()**` methods. Since the app targets **Android 11** and runs a **foreground service**, it is required by the system to display a persistent notification while the service is running. The `createNotificationChannel()` method sets up the notification channel, and `onStartCommand()` triggers the service to run in the foreground using that notification. This ensures the service can operate continuously in the background without being killed by the system.

Now, the most important function for us is `**handleMessage()**`, which contains the core scanning logic.
```java
public void handleMessage(Message msg) {
  
            Intrinsics.checkNotNullParameter(msg, "msg");
  
            try {
  
                System.out.println((Object) "starting file scan...");
  
                File externalStorageDirectory = Environment.getExternalStorageDirectory();
  
                Intrinsics.checkNotNullExpressionValue(externalStorageDirectory, "getExternalStorageDirectory(...)");
  
                Sequence $this$forEach$iv = FilesKt.walk$default(externalStorageDirectory, null, 1, null);
  
                for (Object element$iv : $this$forEach$iv) {
  
                    File file = (File) element$iv;
  
                    if (file.canRead() && file.isFile()) {
  
                        System.out.print((Object) (file.getAbsolutePath() + "..."));
  
                        boolean safe = ScanEngine.INSTANCE.scanFile(file);
  
                        System.out.println((Object) (safe ? "SAFE" : "INFECTED"));
  
                    }
  
                }
  
                System.out.println((Object) "finished file scan!");
  
            } catch (InterruptedException e) {
  
                Thread.currentThread().interrupt();
  
            }
  
            Message $this$handleMessage_u24lambda_u241 = obtainMessage();
  
            $this$handleMessage_u24lambda_u241.arg1 = msg.arg1;
  
            sendMessageDelayed($this$handleMessage_u24lambda_u241, ScanService.SCAN_INTERVAL);
  
        }
```

- It first retrieves the external storage directory using `Environment.getExternalStorageDirectory()`.
    
- Then it recursively walks through all files in that directory using `FilesKt.walk()`.
    
- For each file, it checks if the file is readable and not a directory.
    
- If the check passes, the file is passed to `ScanEngine.INSTANCE.scanFile(file)`
    
- Based on the result, it prints `SAFE` or `INFECTED` to the console using `System.out`.
    
- Finally, it schedules the next scan by sending a delayed message after `SCAN_INTERVAL` (6 seconds), making this a **recurring scan loop**.

## ScanEngine Code Analysis
```java
 public static final Companion INSTANCE = new Companion(null);
  
    private static final HashMap<String, String> KNOWN_MALWARE_SAMPLES = MapsKt.hashMapOf(TuplesKt.to("eicar.com", "3395856ce81f2b7382dee72602f798b642f14140"), TuplesKt.to("eicar.com.txt", "3395856ce81f2b7382dee72602f798b642f14140"), TuplesKt.to("eicar_com.zip", "d27265074c9eac2e2122ed69294dbc4d7cce9141"), TuplesKt.to("eicarcom2.zip", "bec1b52d350d721c7e22a6d4bb0a92909893a3ae"));
```
- **Companion object** is defined to be able to call `scanFile` method from this class without creating an instance every time: `ScanEngine.INSTANCE.scanFile(file);`
- **KNOWN_MALWARE_SAMPLES** maps those known malware files to their corresponding SHA-1 hashes.

```java
 public final boolean scanFile(File file) {
  
            Intrinsics.checkNotNullParameter(file, "file");
  
            try {
  
                String command = "toybox sha1sum " + file.getAbsolutePath();
  
                Process process = new ProcessBuilder(new String[0]).command("sh", "-c", command).directory(Environment.getExternalStorageDirectory()).redirectErrorStream(true).start();
  
                InputStream inputStream = process.getInputStream();
  
                Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
  
                Reader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
  
                BufferedReader bufferedReader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
  
                try {
  
                    BufferedReader reader = bufferedReader;
  
                    String output = reader.readLine();
  
                    Intrinsics.checkNotNull(output);
  
                    Object fileHash = StringsKt.substringBefore$default(output, "  ", (String) null, 2, (Object) null);
  
                    Unit unit = Unit.INSTANCE;
  
                    CloseableKt.closeFinally(bufferedReader, null);
  
                    return !ScanEngine.KNOWN_MALWARE_SAMPLES.containsValue(fileHash);
  
                } finally {
  
                }
  
            } catch (Exception e) {
  
                e.printStackTrace();
  
                return false;
  
            }
  
        }
```
- At first, we have the `command` which uses **toybox's** `sha1sum` (a built-in command-line tool) to calculate the SHA-1 hash of the file. The tool gets the absolute path of the target `ex: toybox sha1sum /storage/emulated/0/Download/sample.txt`
- Then comes our potential **RCE (Remote Code Execution) vulnerability**: the command is executed through a shell using `ProcessBuilder`, which tells the system to open a shell and execute the provided command string.
- `getInputStream()` fetches the output stream from that command execution — this will contain the SHA-1 hash result of the scanned file.
- The result is then processed and prepared to be compared with the known malware hashes stored in `KNOWN_MALWARE_SAMPLES`.
The malware scan is performed solely through hash comparison.
## Logcat 
By running this command to see what the app do
```bash
adb shell pidof com.mobilehackinglab.cyclicscanner
adb logcat --pid=3683
```
![](/assets/img/attachments/cyclic-1.png)
and if there's a file containing a malware as those defined in KNOWN_MALWARE... will print INFECTED

## Exploitation

The vulnerable point here is that `file.getAbsolutePath()` is directly appended as a parameter to the `toybox sha1sum` command **without any validation or sanitization**.

**To achieve RCE (Remote Code Execution):**

- We can inject a command separator (like `;` or `&&`) after the file name so that the additional command gets executed right after calculating the SHA-1 hash.
    
- Then, we check whether our injected command was actually executed
```bash
adb shell
cd  /storage/emulated/0
cd Documents 
echo hello > "test ; touch RCE_DONE"
```
![](/assets/img/attachments/cyclic-2.png)
The first time the app scanned the file we created, the injected command was executed as expected, resulting in the creation of a file named `RCE_DONE`. As shown in the second scan, the app also scanned this newly created file.

![](/assets/img/attachments/cyclic-3.png)
And Exploited! 
for clarification the command when it executed was like 
```bash
toybox sha1sum /storage/emulated/0/Documents/test ; touch RCE_DONE
```
