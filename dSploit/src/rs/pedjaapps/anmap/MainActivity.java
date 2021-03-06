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
package rs.pedjaapps.anmap;

import android.annotation.SuppressLint;
import android.app.ListActivity;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.text.Html;
import android.view.ActionMode;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemLongClickListener;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;

import rs.pedjaapps.anmap.core.ManagedReceiver;
import rs.pedjaapps.anmap.core.MultiAttackService;
import rs.pedjaapps.anmap.core.Plugin;
import rs.pedjaapps.anmap.core.Shell;
import rs.pedjaapps.anmap.core.System;
import rs.pedjaapps.anmap.core.ToolsInstaller;
import rs.pedjaapps.anmap.gui.dialogs.ErrorDialog;
import rs.pedjaapps.anmap.gui.dialogs.FatalDialog;
import rs.pedjaapps.anmap.gui.dialogs.InputDialog;
import rs.pedjaapps.anmap.gui.dialogs.InputDialog.InputDialogListener;
import rs.pedjaapps.anmap.gui.dialogs.MultipleChoiceDialog;
import rs.pedjaapps.anmap.net.Endpoint;
import rs.pedjaapps.anmap.net.Network;
import rs.pedjaapps.anmap.net.NetworkDiscovery;
import rs.pedjaapps.anmap.net.Target;

import static rs.pedjaapps.anmap.net.NetworkDiscovery.ENDPOINT_ADDRESS;
import static rs.pedjaapps.anmap.net.NetworkDiscovery.ENDPOINT_HARDWARE;
import static rs.pedjaapps.anmap.net.NetworkDiscovery.ENDPOINT_NAME;
import static rs.pedjaapps.anmap.net.NetworkDiscovery.ENDPOINT_UPDATE;
import static rs.pedjaapps.anmap.net.NetworkDiscovery.NEW_ENDPOINT;

@SuppressLint("NewApi")
public class MainActivity extends ListActivity
{
    public static final String CONNECTED = "WifiScannerActivity.CONNECTED";
    private String NO_WIFI_UPDATE_MESSAGE;
    private static final int WIFI_CONNECTION_REQUEST = 1012;
    private boolean isWifiAvailable = false;
    private TargetAdapter mTargetAdapter = null;
    private NetworkDiscovery mNetworkDiscovery = null;
    private EndpointReceiver mEndpointReceiver = null;
    private Menu mMenu = null;
    private TextView mUpdateStatus = null;
    private Toast mToast = null;
    private long mLastBackPressTime = 0;
    private ActionMode mActionMode = null;

    private void createUpdateLayout()
    {

        getListView().setVisibility(View.GONE);
        findViewById(R.id.textView).setVisibility(View.GONE);

        RelativeLayout layout = (RelativeLayout) findViewById(R.id.layout);
        LayoutParams params = new LayoutParams(LayoutParams.MATCH_PARENT,
                LayoutParams.MATCH_PARENT);

        mUpdateStatus = new TextView(this);

        mUpdateStatus.setGravity(Gravity.CENTER);
        mUpdateStatus.setLayoutParams(params);
        mUpdateStatus.setText(NO_WIFI_UPDATE_MESSAGE.replace("#STATUS#", "..."));

        layout.addView(mUpdateStatus);

        stopNetworkDiscovery(true);

        if (Build.VERSION.SDK_INT >= 11)
            invalidateOptionsMenu();
    }

    private void createOfflineLayout()
    {

        getListView().setVisibility(View.GONE);
        findViewById(R.id.textView).setVisibility(View.GONE);

        RelativeLayout layout = (RelativeLayout) findViewById(R.id.layout);
        LayoutParams params = new LayoutParams(LayoutParams.MATCH_PARENT,
                LayoutParams.MATCH_PARENT);

        mUpdateStatus = new TextView(this);

        mUpdateStatus.setGravity(Gravity.CENTER);
        mUpdateStatus.setLayoutParams(params);
        mUpdateStatus.setText(getString(R.string.no_connectivity));

        layout.addView(mUpdateStatus);

        stopNetworkDiscovery(true);
        if (Build.VERSION.SDK_INT >= 11)
            invalidateOptionsMenu();
    }

    public void createOnlineLayout()
    {
        mTargetAdapter = new TargetAdapter();

        setListAdapter(mTargetAdapter);

        getListView().setOnItemLongClickListener(new OnItemLongClickListener()
        {
            @Override
            public boolean onItemLongClick(AdapterView<?> parent, View view, int position, long id)
            {
                Target t = System.getTarget(position);
                if (t.getType() == Target.Type.NETWORK)
                {
                    if (mActionMode == null)
                        targetAliasPrompt(t);
                    return true;
                }
                if (mActionMode == null)
                {
                    mTargetAdapter.clearSelection();
                    mActionMode = startActionMode(mActionModeCallback);
                }
                mTargetAdapter.toggleSelection(position);
                return true;
            }
        });

        if (mEndpointReceiver == null)
            mEndpointReceiver = new EndpointReceiver();

        mEndpointReceiver.unregister();

        mEndpointReceiver.register(MainActivity.this);

        startNetworkDiscovery(false);

        // if called for the second time after wifi connection
        if (Build.VERSION.SDK_INT >= 11)
            invalidateOptionsMenu();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode,
                                    Intent intent)
    {
        if (requestCode == WIFI_CONNECTION_REQUEST && resultCode == RESULT_OK && intent.hasExtra(CONNECTED))
        {
            System.reloadNetworkMapping();
            onCreate(null);
        }
    }

    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.target_layout);
        NO_WIFI_UPDATE_MESSAGE = getString(R.string.no_wifi_available);
        isWifiAvailable = Network.isWifiConnected(this);
        boolean connectivityAvailable = isWifiAvailable
                || Network.isConnectivityAvailable(this);


        // make sure system object was correctly initialized during application
        // startup
        if (!System.isInitialized())
        {
            // wifi available but system failed to initialize, this is a fatal
            // :(
            if (isWifiAvailable)
            {
                new FatalDialog(getString(R.string.initialization_error),
                        System.getLastError(), this).show();
                return;
            }
        }

        // initialization ok, but wifi is down
        if (!isWifiAvailable)
        {
            // just inform the user his wifi is down
            if (connectivityAvailable)
                createUpdateLayout();

                // no connectivity at all
            else
                createOfflineLayout();
        }
        // we are online, and the system was already initialized
        else if (mTargetAdapter != null)
            createOnlineLayout();
            // initialize the ui for the first time
        else
        {
            final ProgressDialog dialog = ProgressDialog.show(this, "",
                    getString(R.string.initializing), true, false);

            // this is necessary to not block the user interface while
            // initializing
            new Thread(new Runnable()
            {
                @Override
                public void run()
                {
                    dialog.show();

                    Context appContext = MainActivity.this
                            .getApplicationContext();
                    String fatal = null;
                    ToolsInstaller installer = new ToolsInstaller(appContext);

                    if (!Shell.isBinaryAvailable("killall", true))
                        fatal = getString(R.string.busybox_required);

                    else if (!System.isARM())
                        fatal = getString(R.string.arm_error)
                                + getString(R.string.arm_error2);

                    else if (installer.needed() && !installer.install())
                        fatal = getString(R.string.install_error);


                    dialog.dismiss();

                    if (fatal != null)
                    {
                        final String ffatal = fatal;
                        MainActivity.this.runOnUiThread(new Runnable()
                        {
                            @Override
                            public void run()
                            {
                                new FatalDialog(getString(R.string.error),
                                        ffatal, ffatal.contains(">"),
                                        MainActivity.this).show();
                            }
                        });
                    }

                    MainActivity.this.runOnUiThread(new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            try
                            {
                                createOnlineLayout();
                            }
                            catch (Exception e)
                            {
                                new FatalDialog(getString(R.string.error), e
                                        .getMessage(), MainActivity.this)
                                        .show();
                            }
                        }
                    });
                }
            }).start();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu)
    {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.main, menu);

        if (!isWifiAvailable)
        {
            menu.findItem(R.id.add).setVisible(false);
            menu.findItem(R.id.scan).setVisible(false);
            menu.findItem(R.id.settings).setEnabled(false);
            menu.findItem(R.id.ss_monitor).setEnabled(false);
        }

        mMenu = menu;

        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu)
    {
        MenuItem item = menu.findItem(R.id.ss_monitor);

        if (mNetworkDiscovery != null && mNetworkDiscovery.isRunning())
            item.setTitle(getString(R.string.stop_monitor));
        else
            item.setTitle(getString(R.string.start_monitor));

        mMenu = menu;

        return super.onPrepareOptionsMenu(menu);
    }

    private void targetAliasPrompt(final Target target)
    {

        new InputDialog(getString(R.string.target_alias),
                getString(R.string.set_alias),
                target.hasAlias() ? target.getAlias() : "", true,
                false, MainActivity.this, new InputDialogListener()
        {
            @Override
            public void onInputEntered(String input)
            {
                target.setAlias(input);
                mTargetAdapter.notifyDataSetChanged();
            }
        }).show();
    }

    private ActionMode.Callback mActionModeCallback = new ActionMode.Callback()
    {

        public boolean onCreateActionMode(ActionMode mode, Menu menu)
        {
            MenuInflater inflater = mode.getMenuInflater();
            inflater.inflate(R.menu.main_multi, menu);
            return true;
        }

        public boolean onPrepareActionMode(ActionMode mode, Menu menu)
        {
            int i = mTargetAdapter.getSelectedCount();
            mode.setTitle(i + " " + getString((i > 1 ? R.string.targets_selected : R.string.target_selected)));
            MenuItem item = menu.findItem(R.id.multi_action);
            if (item != null)
                item.setIcon((i > 1 ? android.R.drawable.ic_dialog_dialer : android.R.drawable.ic_menu_edit));
            return false;
        }

        public boolean onActionItemClicked(ActionMode mode, MenuItem item)
        {
            ArrayList<Plugin> commonPlugins = null;

            switch (item.getItemId())
            {
                case R.id.multi_action:
                    final int[] selected = mTargetAdapter.getSelectedPositions();
                    if (selected.length > 1)
                    {
                        commonPlugins = System.getPluginsForTarget(System.getTarget(selected[0]));
                        for (int i = 1; i < selected.length; i++)
                        {
                            ArrayList<Plugin> targetPlugins = System.getPluginsForTarget(System.getTarget(selected[i]));
                            ArrayList<Plugin> removeThem = new ArrayList<Plugin>();
                            for (Plugin p : commonPlugins)
                            {
                                if (!targetPlugins.contains(p))
                                    removeThem.add(p);
                            }
                            for (Plugin p : removeThem)
                            {
                                commonPlugins.remove(p);
                            }
                        }
                        if (commonPlugins.size() > 0)
                        {
                            final int[] actions = new int[commonPlugins.size()];
                            for (int i = 0; i < actions.length; i++)
                                actions[i] = commonPlugins.get(i).getName();

                            (new MultipleChoiceDialog(R.string.choose_method, actions, MainActivity.this, new MultipleChoiceDialog.MultipleChoiceDialogListener()
                            {
                                @Override
                                public void onChoice(int[] choices)
                                {
                                    Intent intent = new Intent(MainActivity.this, MultiAttackService.class);
                                    int[] selectedActions = new int[choices.length];
                                    int j = 0;

                                    for (int i = 0; i < selectedActions.length; i++)
                                        selectedActions[i] = actions[choices[i]];

                                    intent.putExtra(MultiAttackService.MULTI_TARGETS, selected);
                                    intent.putExtra(MultiAttackService.MULTI_ACTIONS, selectedActions);

                                    startService(intent);
                                }
                            })).show();
                        }
                        else
                        {
                            (new ErrorDialog(getString(R.string.error), "no common actions found", MainActivity.this)).show();
                        }
                    }
                    else
                    {
                        targetAliasPrompt(System.getTarget(selected[0]));
                    }
                    mode.finish(); // Action picked, so close the CAB
                    return true;
                default:
                    return false;
            }
        }

        // called when the user exits the action mode
        public void onDestroyActionMode(ActionMode mode)
        {
            mActionMode = null;
            mTargetAdapter.clearSelection();
        }
    };

    public void startNetworkDiscovery(boolean silent)
    {
        stopNetworkDiscovery(silent);

        mNetworkDiscovery = new NetworkDiscovery(this);
        mNetworkDiscovery.start();

        if (!silent)
            Toast.makeText(this, getString(R.string.net_discovery_started),
                    Toast.LENGTH_SHORT).show();
    }

    public void stopNetworkDiscovery(boolean silent, boolean joinThreads)
    {
        if (mNetworkDiscovery != null)
        {
            if (mNetworkDiscovery.isRunning())
            {
                mNetworkDiscovery.exit();

                if (joinThreads)
                {
                    try
                    {
                        mNetworkDiscovery.join();
                    }
                    catch (Exception e)
                    {
                    }
                }

                if (!silent)
                    Toast.makeText(this,
                            getString(R.string.net_discovery_stopped),
                            Toast.LENGTH_SHORT).show();
            }

            mNetworkDiscovery = null;
        }
    }

    public void stopNetworkDiscovery(boolean silent)
    {
        stopNetworkDiscovery(silent, true);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item)
    {
        switch (item.getItemId())
        {

            case R.id.add:
                new InputDialog(getString(R.string.add_custom_target),
                        getString(R.string.enter_url), MainActivity.this,
                        new InputDialogListener()
                        {
                            @Override
                            public void onInputEntered(String input)
                            {
                                final Target target = Target.getFromString(input);
                                if (target != null)
                                {
                                    // refresh the target listview
                                    MainActivity.this.runOnUiThread(new Runnable()
                                    {
                                        @Override
                                        public void run()
                                        {
                                            if (System.addOrderedTarget(target)
                                                    && mTargetAdapter != null)
                                            {
                                                mTargetAdapter
                                                        .notifyDataSetChanged();
                                            }
                                        }
                                    });
                                }
                                else
                                    new ErrorDialog(getString(R.string.error),
                                            getString(R.string.invalid_target),
                                            MainActivity.this).show();
                            }
                        }).show();
                return true;

            case R.id.scan:
                if (mMenu != null)
                    mMenu.findItem(R.id.scan).setActionView(new ProgressBar(this));

                new Thread(new Runnable()
                {
                    @Override
                    public void run()
                    {
                        startNetworkDiscovery(true);

                        MainActivity.this.runOnUiThread(new Runnable()
                        {
                            @Override
                            public void run()
                            {
                                if (mMenu != null)
                                    mMenu.findItem(R.id.scan).setActionView(null);
                            }
                        });
                    }
                }).start();

                item.setTitle(getString(R.string.stop_monitor));
                return true;

            case R.id.settings:
                startActivity(new Intent(MainActivity.this, SettingsActivity.class));
                return true;

            case R.id.ss_monitor:
                if (mNetworkDiscovery != null && mNetworkDiscovery.isRunning())
                {
                    stopNetworkDiscovery(false);

                    item.setTitle(getString(R.string.start_monitor));
                }
                else
                {
                    try
                    {
                        startNetworkDiscovery(false);

                        item.setTitle(getString(R.string.stop_monitor));
                    }
                    catch (Exception e)
                    {
                        new ErrorDialog(getString(R.string.error), e.getMessage(), MainActivity.this).show();
                    }
                }
                return true;

            default:
                return super.onOptionsItemSelected(item);

        }

    }

    @Override
    protected void onListItemClick(ListView l, View v, int position, long id)
    {
        super.onListItemClick(l, v, position, id);

        if (mActionMode != null)
        {
            ((TargetAdapter) getListAdapter()).toggleSelection(position);
            return;
        }

        new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                /*
				 * Do not wait network discovery threads to exit since this
				 * would cause a long waiting when it's scanning big networks.
				 */
                stopNetworkDiscovery(true, false);

                startActivityForResult(new Intent(MainActivity.this, ActionActivity.class), WIFI_CONNECTION_REQUEST);

                overridePendingTransition(R.anim.slide_in_left, R.anim.slide_out_left);
            }
        }).start();

        System.setCurrentTarget(position);
    }

    @Override
    public void onBackPressed()
    {
        if (mLastBackPressTime < java.lang.System.currentTimeMillis() - 4000)
        {
            mToast = Toast.makeText(this, getString(R.string.press_back),
                    Toast.LENGTH_SHORT);
            mToast.show();
            mLastBackPressTime = java.lang.System.currentTimeMillis();
        }
        else
        {
            if (mToast != null)
                mToast.cancel();

            super.onBackPressed();
            mLastBackPressTime = 0;
        }
    }

    @Override
    public void onDestroy()
    {
        stopNetworkDiscovery(true);

        if (mEndpointReceiver != null)
            mEndpointReceiver.unregister();

        // make sure no zombie process is running before destroying the activity
        System.clean(true);

        super.onDestroy();
    }

    public class TargetAdapter extends ArrayAdapter<Target>
    {
        public TargetAdapter()
        {
            super(MainActivity.this, R.layout.target_list_item);
        }

        @Override
        public int getCount()
        {
            return System.getTargets().size();
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent)
        {
            View row = convertView;
            TargetHolder holder;

            if (row == null)
            {
                LayoutInflater inflater = (LayoutInflater) MainActivity.this.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
                row = inflater.inflate(R.layout.target_list_item, parent, false);

                holder = new TargetHolder();
                holder.itemImage = (ImageView) (row != null ? row
                        .findViewById(R.id.itemIcon) : null);
                holder.itemTitle = (TextView) (row != null ? row
                        .findViewById(R.id.itemTitle) : null);
                holder.itemDescription = (TextView) (row != null ? row
                        .findViewById(R.id.itemDescription) : null);

                if (row != null)
                    row.setTag(holder);
            }
            else
                holder = (TargetHolder) row.getTag();

            Target target = System.getTarget(position);

            if (target.hasAlias())
                holder.itemTitle.setText(Html.fromHtml("<b>"
                        + target.getAlias() + "</b> <small>( "
                        + target.getDisplayAddress() + " )</small>"));

            else
                holder.itemTitle.setText(target.toString());

            holder.itemTitle.setTextColor(getResources().getColor((target.isConnected() ? R.color.app_color : R.color.gray_text)));

            if (row != null)
                row.setBackgroundColor(getResources().getColor((target.isSelected() ? R.color.selectable_blue : android.R.color.transparent)));

            holder.itemTitle.setTypeface(null, Typeface.NORMAL);
            holder.itemImage.setImageResource(target.getDrawableResourceId());
            holder.itemDescription.setText(target.getDescription());

            return row;
        }

        public void clearSelection()
        {
            for (Target t : System.getTargets())
                t.setSelected(false);
            notifyDataSetChanged();
            if (mActionMode != null)
                mActionMode.finish();
        }

        public void toggleSelection(int position)
        {
            Target t = System.getTarget(position);
            t.setSelected(!t.isSelected());
            notifyDataSetChanged();
            if (mActionMode != null)
            {
                if (getSelectedCount() > 0)
                    mActionMode.invalidate();
                else
                    mActionMode.finish();
            }
        }

        public int getSelectedCount()
        {
            int i = 0;
            for (Target t : System.getTargets())
                if (t.isSelected())
                    i++;
            return i;
        }

        public ArrayList<Target> getSelected()
        {
            ArrayList<Target> result = new ArrayList<Target>();
            for (Target t : System.getTargets())
                if (t.isSelected())
                    result.add(t);
            return result;
        }

        public int[] getSelectedPositions()
        {
            int[] res = new int[getSelectedCount()];
            int j = 0;

            for (int i = 0; i < System.getTargets().size(); i++)
                if (System.getTarget(i).isSelected())
                    res[j++] = i;
            return res;
        }

        class TargetHolder
        {
            ImageView itemImage;
            TextView itemTitle;
            TextView itemDescription;
        }
    }

    private class EndpointReceiver extends ManagedReceiver
    {
        private IntentFilter mFilter = null;

        public EndpointReceiver()
        {
            mFilter = new IntentFilter();

            mFilter.addAction(NEW_ENDPOINT);
            mFilter.addAction(ENDPOINT_UPDATE);
        }

        public IntentFilter getFilter()
        {
            return mFilter;
        }

        @SuppressWarnings("ConstantConditions")
        @Override
        public void onReceive(Context context, Intent intent)
        {
            if (intent.getAction() != null)
                if (intent.getAction().equals(NEW_ENDPOINT))
                {
                    String address = (String) intent.getExtras().get(
                            ENDPOINT_ADDRESS), hardware = (String) intent
                            .getExtras().get(ENDPOINT_HARDWARE), name = (String) intent
                            .getExtras().get(ENDPOINT_NAME);
                    final Target target = Target.getFromString(address);

                    if (target != null && target.getEndpoint() != null)
                    {
                        if (name != null && !name.isEmpty())
                            target.setAlias(name);

                        target.getEndpoint().setHardware(
                                Endpoint.parseMacAddress(hardware));

                        // refresh the target listview
                        MainActivity.this.runOnUiThread(new Runnable()
                        {
                            @Override
                            public void run()
                            {
                                if (System.addOrderedTarget(target))
                                {
                                    mTargetAdapter.notifyDataSetChanged();
                                }
                            }
                        });
                    }
                }
                else if (intent.getAction().equals(ENDPOINT_UPDATE))
                {
                    // refresh the target listview
                    MainActivity.this.runOnUiThread(new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            mTargetAdapter.notifyDataSetChanged();
                        }
                    });
                }
        }
    }
}
