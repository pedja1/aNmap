package rs.pedjaapps.anmap.core;

import android.util.Log;

public class Logger
{
    private static final String TAG = "DSPLOIT";

    private static void log(int priority, String message)
    {
        StackTraceElement[] els = Thread.currentThread().getStackTrace();
        StackTraceElement caller = null;

        for (StackTraceElement el : els)
        {
            // search for the last stack frame in our namespace
            if (el.getClassName().startsWith("rs.pedjaapps.anmap"))
            {
                caller = el;
            }
        }

        String Tag = TAG + "[" + caller.getClassName().replace("rs.pedjaapps.anmap.", "") + "." + caller.getMethodName() + "]";

        Log.println(priority, Tag, message);
    }

    public static void debug(String message)
    {
        log(Log.DEBUG, message);
    }

    public static void info(String message)
    {
        log(Log.INFO, message);
    }

    public static void warning(String message)
    {
        log(Log.WARN, message);
    }

    public static void error(String message)
    {
        log(Log.ERROR, message);
    }
}
