package com.gantix.JailMonkey.HookDetection;

import android.app.ActivityManager;
import android.content.Context;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import java.util.Arrays;
import java.util.List;

public class HookDetectionCheck {

    /**
     * Detects if there is any suspicious installed application.
     *
     * @return <code>true</code> if some bad application is installed, <code>false</code> otherwise.
     */
    public static boolean hookDetected(Context context) {
        PackageManager packageManager = context.getPackageManager();
        List<ApplicationInfo> applicationInfoList = packageManager.getInstalledApplications(PackageManager.GET_META_DATA);
        String[] dangerousPackages = {'de.robv.android.xposed.installer', 'com.saurik.substrate', 'de.robv.android.xposed', 'com.savageorgiev.blockthis', 'org.adaway', 'com.com.rootfirewallkeyapp', 'org.blokada.origin.alarm', 'com.com.android.adfree', 'com.com.adblockfast', 'com.com.litenorootadremover', 'com.com.mobile.security', 'com.com.adaware', 'org.com.dns66', 'org.com.origin.alarm', 'tw.com.xposed.minminguard', 'com.com.advanishlite', 'com.com.android', 'com.com.security', 'org.com.datablocker', 'comm.com.addblocker', 'com.com.adclear', 'com.com.addetector', 'com.com.swisscodemonkeys.detector', 'com.com.freeadblockerbrowser', 'org.com.browser', 'vadim.com.sniffer', 'com.com.blocker', 'com.com.stopadandroid', 'jp.co.com.android.packetcapture', 'app.com.sslcapturess', 'app.com.sslcapture', 'com.minhui.networkcapture', 'com.evbadroid.proxymon', 'org.com.android', 'com.bigtincan.android.adfree', 'com.rocketshipapps.adblockfast', 'com.atejapps.litenorootadremover', 'com.trustgo.mobile.security', 'com.keerby.adaware', 'org.jak_linux.dns66', 'org.blokada.origin.alarm', 'tw.fatminmin.xposed.minminguard', 'org.adaway', 'com.atejapps.advanishlite', 'com.adguard.android', 'org.dotcode.datablocker', 'comm.stackapps.addblocker', 'com.seven.adclear', 'com.trustgo.addetector', 'com.appspot.swisscodemonkeys.detector', 'com.hsv.freeadblockerbrowser', 'vadim.ofer.sniffer', 'com.notification.blocker', 'com.stopad.stopadandroid', 'jp.co.taosoftware.android.packetcapture', 'app.greyshirts.sslcapturess', 'app.greyshirts.sslcapture', 'com.savageorgiev.blockthis', 'org.adblockplus.android', 'com.packagesniffer.frtparlak', 'com.guoshi.httpcanary', 'com.guoshi.httpcanary.premium', 'com.minhui.networkcapture.pro', 'com.dans.apps.webd'};

        for (ApplicationInfo applicationInfo : applicationInfoList) {
            if (Arrays.asList(dangerousPackages).contains(applicationInfo.packageName)) {
                return true;
            }
        }

        return advancedHookDetection(context);
    }

    private static boolean advancedHookDetection(Context context) {
        try {
            throw new Exception();
        } catch (Exception e) {
            int zygoteInitCallCount = 0;
            for (StackTraceElement stackTraceElement : e.getStackTrace()) {
                if (stackTraceElement.getClassName().equals("com.android.internal.os.ZygoteInit")) {
                    zygoteInitCallCount++;
                    if (zygoteInitCallCount == 2) {
                        return true;
                    }
                }

                if (stackTraceElement.getClassName().equals("com.saurik.substrate.MS$2") &&
                        stackTraceElement.getMethodName().equals("invoked")) {
                    return true;
                }

                if (stackTraceElement.getClassName().equals("de.robv.android.xposed.XposedBridge") &&
                        stackTraceElement.getMethodName().equals("main")) {
                    return true;
                }

                if (stackTraceElement.getClassName().equals("de.robv.android.xposed.XposedBridge") &&
                        stackTraceElement.getMethodName().equals("handleHookedMethod")) {
                    return true;
                }
            }
        }

        return checkFrida(context);
    }

    private static boolean checkFrida(Context context) {
        ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningServiceInfo> runningServices = activityManager.getRunningServices(300);

        if (runningServices != null) {
            for (int i = 0; i < runningServices.size(); ++i) {
                if (runningServices.get(i).process.contains("fridaserver")) {
                    return true;
                }
            }
        }

        return false;
    }
}
