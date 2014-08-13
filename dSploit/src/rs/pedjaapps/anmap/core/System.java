/*
 * This file is part of the dSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
 *
 * dSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package rs.pedjaapps.anmap.core;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.ActivityManager.RunningServiceInfo;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiManager.WifiLock;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;
import android.preference.PreferenceManager;
import android.util.SparseIntArray;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import rs.pedjaapps.anmap.MainActivity;
import rs.pedjaapps.anmap.R;
import rs.pedjaapps.anmap.net.Endpoint;
import rs.pedjaapps.anmap.net.Network;
import rs.pedjaapps.anmap.net.Network.Protocol;
import rs.pedjaapps.anmap.net.Target;
import rs.pedjaapps.anmap.net.Target.Port;
import rs.pedjaapps.anmap.net.Target.Type;
import rs.pedjaapps.anmap.tools.Fusemounts;
import rs.pedjaapps.anmap.tools.IPTables;
import rs.pedjaapps.anmap.tools.NMap;

public class System
{
    public static final String SESSION_MAGIC = "DSS";

    private static final String ERROR_LOG_FILENAME = "anmap-debug-error.log";
    private static final Pattern SERVICE_PARSER = Pattern.compile("^([^\\s]+)\\s+(\\d+).*$", Pattern.CASE_INSENSITIVE);

    public static final String IPV4_FORWARD_FILEPATH = "/proc/sys/net/ipv4/ip_forward";

    private static boolean mInitialized = false;
    private static String mLastError = "";
    private static String mSuPath = null;
    private static Context mContext = null;
    private static WifiLock mWifiLock = null;
    private static WakeLock mWakeLock = null;
    private static Network mNetwork = null;
    private static final Vector<Target> mTargets = new Vector<Target>();
    private static int mCurrentTarget = 0;
    private static Map<String, String> mServices = null;
    private static Map<String, String> mPorts = null;
    private static Map<String, String> mVendors = null;
    private static SparseIntArray mOpenPorts = null;

    // registered plugins
    private static ArrayList<Plugin> mPlugins = null;
    private static Plugin mCurrentPlugin = null;
    // tools singleton
    private static NMap mNmap = null;
    private static IPTables mIptables = null;
    private static Fusemounts mFusemounts = null;

    private static String mStoragePath = null;
    private static String mSessionName = null;

    private static String mLocalApkVersion = null;

    private static Object mCustomData = null;

    public static void init(Context context) throws Exception
    {
        mContext = context;
        try
        {
            mStoragePath = getSettings().getString("PREF_SAVE_PATH", Environment.getExternalStorageDirectory().toString());
            mSessionName = "anmap-session-" + java.lang.System.currentTimeMillis();
            mPlugins = new ArrayList<Plugin>();
            mOpenPorts = new SparseIntArray(3);

            // if we are here, network initialization didn't throw any error, lock wifi
            WifiManager wifiManager = (WifiManager) mContext.getSystemService(Context.WIFI_SERVICE);

            if (mWifiLock == null)
                mWifiLock = wifiManager.createWifiLock(WifiManager.WIFI_MODE_FULL, "wifiLock");

            if (!mWifiLock.isHeld())
                mWifiLock.acquire();

            // wake lock if enabled
            if (getSettings().getBoolean("PREF_WAKE_LOCK", true))
            {
                PowerManager powerManager = (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);

                if (mWakeLock == null)
                    mWakeLock = powerManager.newWakeLock(PowerManager.FULL_WAKE_LOCK, "wakeLock");

                if (!mWakeLock.isHeld())
                    mWakeLock.acquire();
            }

            reloadTools();

            // initialize network data at the end
            mNetwork = new Network(mContext);

            Target network = new Target(mNetwork),
                    gateway = new Target(mNetwork.getGatewayAddress(), mNetwork.getGatewayHardware()),
                    device = new Target(mNetwork.getLocalAddress(), mNetwork.getLocalHardware());

            gateway.setAlias(mNetwork.getSSID());
            device.setAlias(android.os.Build.MODEL);

            //mTargets.add(network);
            mTargets.add(gateway);
            mTargets.add(device);

            mInitialized = true;
        }
        catch (Exception e)
        {
            errorLogging(e);

            throw e;
        }
    }

    public static void reloadTools()
    {
        mNmap = new NMap(mContext);
        mIptables = new IPTables();
        mFusemounts = new Fusemounts(mContext);
    }

    public static void reloadNetworkMapping()
    {
        try
        {
            mNetwork = new Network(mContext);

            Target network = new Target(mNetwork),
                    gateway = new Target(mNetwork.getGatewayAddress(), mNetwork.getGatewayHardware()),
                    device = new Target(mNetwork.getLocalAddress(), mNetwork.getLocalHardware());

            gateway.setAlias(mNetwork.getSSID());
            device.setAlias(android.os.Build.MODEL);

            mTargets.clear();
            mTargets.add(network);
            mTargets.add(gateway);
            mTargets.add(device);

            mInitialized = true;
        }
        catch (NoRouteToHostException nrthe)
        {
            // swallow bitch
        }
        catch (Exception e)
        {
            errorLogging(e);
        }
    }

    public static boolean checkNetworking(final Activity current)
    {
        if (!Network.isWifiConnected(mContext))
        {
            AlertDialog.Builder builder = new AlertDialog.Builder(current);

            builder.setCancelable(false);
            builder.setTitle(current.getString(R.string.error));
            builder.setMessage(current.getString(R.string.wifi_went_down));
            builder.setPositiveButton("Ok", new DialogInterface.OnClickListener()
            {
                @Override
                public void onClick(DialogInterface dialog, int which)
                {
                    dialog.dismiss();

                    Bundle bundle = new Bundle();
                    bundle.putBoolean(MainActivity.CONNECTED, false);

                    Intent intent = new Intent();
                    intent.putExtras(bundle);

                    current.setResult(Activity.RESULT_OK, intent);
                    current.finish();
                }
            });

            AlertDialog alert = builder.create();
            alert.show();

            return false;
        }

        return true;
    }

    public static void setLastError(String error)
    {
        mLastError = error;
    }

    public static String getLastError()
    {
        return mLastError;
    }

    public static synchronized void errorLogging(Exception e)
    {
        String message = "Unknown error.",
                trace = "Unknown trace.",
                filename = (new File(Environment.getExternalStorageDirectory().toString(), ERROR_LOG_FILENAME)).getAbsolutePath();

        if (e != null)
        {
            if (e.getMessage() != null && !e.getMessage().isEmpty())
                message = e.getMessage();

            else if (e.toString() != null)
                message = e.toString();

            if (message.equals(mLastError))
                return;

            Writer sWriter = new StringWriter();
            PrintWriter pWriter = new PrintWriter(sWriter);

            e.printStackTrace(pWriter);

            trace = sWriter.toString();

            if (mContext != null && getSettings().getBoolean("PREF_DEBUG_ERROR_LOGGING", false))
            {
                try
                {
                    FileWriter fWriter = new FileWriter(filename, true);
                    BufferedWriter bWriter = new BufferedWriter(fWriter);

                    bWriter.write(trace);

                    bWriter.close();
                }
                catch (IOException ioe)
                {
                    Logger.error(ioe.toString());
                }
            }
        }

        setLastError(message);
        Logger.error(message);
        Logger.error(trace);
    }

    public static synchronized void errorLog(String tag, String data)
    {
        String filename = (new File(Environment.getExternalStorageDirectory().toString(), ERROR_LOG_FILENAME)).getAbsolutePath();

        data = data.trim();

        if (mContext != null && getSettings().getBoolean("PREF_DEBUG_ERROR_LOGGING", false))
        {
            try
            {
                FileWriter fWriter = new FileWriter(filename, true);
                BufferedWriter bWriter = new BufferedWriter(fWriter);

                bWriter.write(data);

                bWriter.close();
            }
            catch (IOException ioe)
            {
                Logger.error(ioe.toString());
            }
        }

        Logger.error(data);
    }

    public static boolean isARM()
    {
        String abi = Build.CPU_ABI;

        Logger.debug("Build.CPU_ABI = " + abi);

        return Build.CPU_ABI.toLowerCase().startsWith("armeabi");
    }

    public static synchronized void setCustomData(Object data)
    {
        mCustomData = data;
    }

    public static Object getCustomData()
    {
        return mCustomData;
    }

    public static InputStream getRawResource(int id)
    {
        return mContext.getResources().openRawResource(id);
    }

    public static String getDefaultRubyPath()
    {
        return mContext.getFilesDir().getAbsolutePath() + "/ruby";
    }

    public static String getRubyPath()
    {
        return getSettings().getString("RUBY_DIR", getDefaultRubyPath());
    }

    public static String getDefaultMsfPath()
    {
        return mContext.getFilesDir().getAbsolutePath() + "/msf";
    }

    public static String getMsfPath()
    {
        return getSettings().getString("MSF_DIR", getDefaultMsfPath());
    }

    public static String getFifosPath()
    {
        return mContext.getFilesDir().getAbsolutePath() + "/fifos/";
    }

    public static String getToolsPath()
    {
        return mContext.getFilesDir().getAbsolutePath() + "/tools/";
    }

    public static String getSuPath()
    {

        if (mSuPath != null)
            return mSuPath;

        try
        {
            Process process = Runtime.getRuntime().exec("which su");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = reader.readLine()) != null)
            {
                if (!line.isEmpty() && line.startsWith("/"))
                {
                    mSuPath = line;
                    break;
                }
            }

            return mSuPath;
        }
        catch (Exception e)
        {
            errorLogging(e);
        }

        return "su";
    }

    private static void preloadServices()
    {
        if (mServices == null || mPorts == null)
        {
            try
            {
                // preload network service map and mac vendors
                mServices = new HashMap<String, String>();
                mPorts = new HashMap<String, String>();

                @SuppressWarnings("ConstantConditions")
                FileInputStream fstream = new FileInputStream(mContext.getFilesDir().getAbsolutePath() + "/tools/nmap/nmap-services");

                DataInputStream in = new DataInputStream(fstream);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                String line;
                Matcher matcher;

                while ((line = reader.readLine()) != null)
                {
                    line = line.trim();

                    if ((matcher = SERVICE_PARSER.matcher(line)) != null && matcher.find())
                    {
                        String proto = matcher.group(1),
                                port = matcher.group(2);

                        mServices.put(proto, port);
                        mPorts.put(port, proto);
                    }
                }

                in.close();
            }
            catch (Exception e)
            {
                errorLogging(e);
            }
        }
    }

    private static void preloadVendors()
    {
        if (mVendors == null)
        {
            try
            {
                mVendors = new HashMap<String, String>();
                @SuppressWarnings("ConstantConditions")
                FileInputStream fstream = new FileInputStream(mContext.getFilesDir().getAbsolutePath() + "/tools/nmap/nmap-mac-prefixes");

                DataInputStream in = new DataInputStream(fstream);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                String line;

                while ((line = reader.readLine()) != null)
                {
                    line = line.trim();
                    if (!line.startsWith("#") && !line.isEmpty())
                    {
                        String[] tokens = line.split(" ", 2);

                        if (tokens.length == 2)
                            mVendors.put(tokens[0], tokens[1]);
                    }
                }

                in.close();
            }
            catch (Exception e)
            {
                errorLogging(e);
            }
        }
    }

    public static String getSessionName()
    {
        return mSessionName;
    }

    public static String getStoragePath()
    {
        return mStoragePath;
    }

    public static SharedPreferences getSettings()
    {
        return PreferenceManager.getDefaultSharedPreferences(mContext);
    }

    public static String getAppVersionName()
    {
        if (mLocalApkVersion != null)
            return mLocalApkVersion;
        try
        {
            PackageManager manager = mContext.getPackageManager();
            PackageInfo info = manager != null ? manager.getPackageInfo(mContext.getPackageName(), 0) : null;

            return (mLocalApkVersion = info.versionName);
        }
        catch (NameNotFoundException e)
        {
            errorLogging(e);
        }

        return "?";
    }

    /**
     * reade the first line of a file
     *
     * @param filePath path of the file to read from
     * @return the first line of the file or {@code null} if an error occurs
     */
    private static String readFirstLine(String filePath)
    {
        BufferedReader reader = null;

        if (filePath == null)
            return null;

        try
        {
            reader = new BufferedReader(new FileReader(filePath));
            return reader.readLine().trim();
        }
        catch (IOException e)
        {
            Logger.debug(e.getMessage());
        }
        finally
        {
            try
            {
                if (reader != null)
                    reader.close();
            }
            catch (IOException e)
            {
                //ignored
            }
        }
        return null;
    }

    public static boolean isServiceRunning(String name)
    {
        ActivityManager manager = (ActivityManager) mContext.getSystemService(Context.ACTIVITY_SERVICE);

        //noinspection ConstantConditions
        for (RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE))
        {
            if (name.equals(service.service.getClassName()))
                return true;
        }

        return false;
    }

    public static boolean isPortAvailable(int port)
    {
        boolean available = true;

        int available_code = mOpenPorts.get(port);

        if (available_code != 0)
            return available_code != 1;

        try
        {
            // attempt 3 times since proxy and server could be still releasing
            // their ports
            for (int i = 0; i < 3; i++)
            {
                Socket channel = new Socket();
                InetSocketAddress address = new InetSocketAddress(InetAddress.getByName(mNetwork.getLocalAddressAsString()), port);

                channel.connect(address, 200);

                available = !channel.isConnected();

                channel.close();

                if (available)
                    break;

                Thread.sleep(200);
            }
        }
        catch (Exception e)
        {
            available = true;
        }

        mOpenPorts.put(port, available ? 2 : 1);

        return available;
    }

    public static NMap getNMap()
    {
        return mNmap;
    }

    public static IPTables getIPTables()
    {
        return mIptables;
    }

    public static Fusemounts getFusemounts()
    {
        return mFusemounts;
    }

    public static String getImageMimeType(String fileName)
    {
        String type = "image/jpeg",
                name = fileName.toLowerCase();

        if (name.endsWith(".jpeg") || name.endsWith(".jpg"))
            type = "image/jpeg";

        else if (name.endsWith(".png"))
            type = "image/png";

        else if (name.endsWith(".gif"))
            type = "image/gif";

        else if (name.endsWith(".tiff"))
            type = "image/tiff";

        return type;
    }

    public static void reset() throws NoRouteToHostException, SocketException
    {
        mTargets.clear();

        // local network
        mTargets.add(new Target(System.getNetwork()));
        // network gateway
        mTargets.add(new Target(System.getNetwork().getGatewayAddress(), System.getNetwork().getGatewayHardware()));
        // device network address
        mTargets.add(new Target(System.getNetwork().getLocalAddress(), System.getNetwork().getLocalHardware()));

        mCurrentTarget = 0;
    }

    public static boolean isInitialized()
    {
        return mInitialized;
    }

    public static String getMacVendor(byte[] mac)
    {
        preloadVendors();

        if (mac != null && mac.length >= 3)
            return mVendors.get(String.format("%02X%02X%02X", mac[0], mac[1], mac[2]));
        else
            return null;
    }

    public static String getProtocolByPort(String port)
    {
        preloadServices();

        return mPorts.containsKey(port) ? mPorts.get(port) : null;
    }

    public static int getPortByProtocol(String protocol)
    {
        preloadServices();

        return mServices.containsKey(protocol) ? Integer.parseInt(mServices.get(protocol)) : 0;
    }

    public static Context getContext()
    {
        return mContext;
    }

    public static Network getNetwork()
    {
        return mNetwork;
    }

    public static Vector<Target> getTargets()
    {
        return mTargets;
    }

    public static ArrayList<Target> getTargetsByType(Target.Type type)
    {
        ArrayList<Target> filtered = new ArrayList<Target>();

        for (Target target : mTargets)
        {
            if (target.getType() == type)
                filtered.add(target);
        }

        return filtered;
    }

    public static ArrayList<Endpoint> getNetworkEndpoints()
    {
        ArrayList<Endpoint> filtered = new ArrayList<Endpoint>();

        for (Target target : mTargets)
        {
            if (target.getType() == Type.ENDPOINT)
                filtered.add(target.getEndpoint());
        }

        return filtered;
    }

    public static void addTarget(int index, Target target)
    {
        mTargets.add(index, target);
        // update current target index
        if (mCurrentTarget >= index)
            mCurrentTarget++;
    }

    public static void addTarget(Target target)
    {
        mTargets.add(target);
    }

    public static boolean addOrderedTarget(Target target)
    {
        if (target != null && !hasTarget(target))
        {
            for (int i = 0; i < getTargets().size(); i++)
            {
                if (getTarget(i).comesAfter(target))
                {
                    addTarget(i, target);
                    return true;
                }
            }

            addTarget(target);

            return true;
        }

        return false;
    }

    public static Target getTarget(int index)
    {
        return mTargets.get(index);
    }

    public static boolean hasTarget(Target target)
    {
        return mTargets.contains(target);
    }

    public static void setCurrentTarget(int index)
    {
        mCurrentTarget = index;
    }

    public static Target getCurrentTarget()
    {
        return getTarget(mCurrentTarget);
    }

    public static Target getTargetByAddress(String address)
    {
        int i, size = mTargets.size();

        for (i = 0; i < size; i++)
        {
            synchronized (mTargets)
            {
                Target t = mTargets.get(i);

                if (t != null && t.getAddress() != null && t.getAddress().getHostAddress().equals(address))
                    return t;
            }
        }

        return null;
    }

    public static void registerPlugin(Plugin plugin)
    {
        mPlugins.add(plugin);
    }

    public static ArrayList<Plugin> getPlugins()
    {
        return mPlugins;
    }

    public static ArrayList<Plugin> getPluginsForTarget(Target target)
    {
        ArrayList<Plugin> filtered = new ArrayList<Plugin>();

        if (target != null)
        {
            for (Plugin plugin : mPlugins)
                if (plugin.isAllowedTarget(target))
                    filtered.add(plugin);
        }

        return filtered;
    }

    public static ArrayList<Plugin> getPluginsForTarget()
    {
        return getPluginsForTarget(getCurrentTarget());
    }

    public static void setCurrentPlugin(Plugin plugin)
    {
        Logger.debug("Setting current plugin : " + mContext.getString(plugin.getName()));

        mCurrentPlugin = plugin;
    }

    public static Plugin getCurrentPlugin()
    {
        return mCurrentPlugin;
    }

    public static void addOpenPort(int port, Protocol protocol)
    {
        addOpenPort(port, protocol, null, null);
    }

    public static void addOpenPort(int port, Protocol protocol, String service)
    {
        addOpenPort(port, protocol, service, null);
    }

    public static void addOpenPort(int port, Protocol protocol, String service, String version)
    {
        Port p = new Port(port, protocol, service, version);

        getCurrentTarget().addOpenPort(p);

        for (Plugin plugin : getPluginsForTarget())
        {
            plugin.onTargetNewOpenPort(getCurrentTarget(), p);
        }
    }

    public static String getGatewayAddress()
    {
        return mNetwork.getGatewayAddress().getHostAddress();
    }

    public static boolean isForwardingEnabled()
    {
        boolean forwarding = false;
        BufferedReader reader;
        String line;

        try
        {
            reader = new BufferedReader(new FileReader(IPV4_FORWARD_FILEPATH));
            line = reader.readLine().trim();
            forwarding = line.equals("1");

            reader.close();

        }
        catch (IOException e)
        {
            Logger.warning(e.toString());
        }

        return forwarding;
    }

    public static void setForwarding(boolean enabled)
    {
        Logger.debug("Setting ipv4 forwarding to " + enabled);

        String status = (enabled ? "1" : "0"),
                cmd = "echo " + status + " > " + IPV4_FORWARD_FILEPATH;

        try
        {
            Shell.exec(cmd);
        }
        catch (Exception e)
        {
            errorLogging(e);
        }
    }

    public static void clean(boolean releaseLocks)
    {
        setForwarding(false);

        try
        {
            String tools = "msfrpcd ";
            for (String tool : ToolsInstaller.TOOLS)
                tools += tool + " ";

            Logger.debug("Killing any running instance of " + tools);
            Shell.exec("killall -9 " + tools.trim());

            if (releaseLocks)
            {
                Logger.debug("Releasing locks.");

                if (mWifiLock != null && mWifiLock.isHeld())
                    mWifiLock.release();

                if (mWakeLock != null && mWakeLock.isHeld())
                    mWakeLock.release();
            }
        }
        catch (Exception e)
        {
            errorLogging(e);
        }
    }

}
