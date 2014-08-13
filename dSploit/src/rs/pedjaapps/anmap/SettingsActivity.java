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

import android.content.BroadcastReceiver;
import android.content.Intent;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.Preference.OnPreferenceClickListener;
import android.preference.PreferenceActivity;
import android.view.MenuItem;
import android.widget.Toast;

import java.io.File;

import rs.pedjaapps.anmap.core.Logger;
import rs.pedjaapps.anmap.core.Shell;
import rs.pedjaapps.anmap.gui.DirectoryPicker;
import rs.pedjaapps.anmap.gui.dialogs.ConfirmDialog;

@SuppressWarnings("deprecation")
public class SettingsActivity extends PreferenceActivity
{
    public static final int SETTINGS_DONE = 101285;
    public static final String SETTINGS_WIPE_START = "SettingsActivity.WIPE_START";
    public static final String SETTINGS_WIPE_DIR = "SettingsActivity.data.WIPE_DIR";

    private BroadcastReceiver mReceiver = null;

    @SuppressWarnings("ConstantConditions")
    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        getActionBar().setDisplayHomeAsUpEnabled(true);
        addPreferencesFromResource(R.xml.preferences);

        Preference mSavePath = getPreferenceScreen().findPreference("PREF_SAVE_PATH");

        mSavePath.setOnPreferenceClickListener(new OnPreferenceClickListener()
        {
            @Override
            public boolean onPreferenceClick(Preference preference)
            {
                startDirectoryPicker(preference);
                return true;
            }
        });

    }

    private void wipe_prompt_older(final File oldDir)
    {
        new ConfirmDialog(getString(R.string.warning), getString(R.string.delete_previous_location), SettingsActivity.this, new ConfirmDialog.ConfirmDialogListener()
        {
            @Override
            public void onConfirm()
            {
                Intent i = new Intent(SETTINGS_WIPE_START);
                i.putExtra(SETTINGS_WIPE_DIR, oldDir.getAbsolutePath());
                sendBroadcast(i);
            }

            @Override
            public void onCancel()
            {

            }
        }).show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent intent)
    {
        if (requestCode == DirectoryPicker.PICK_DIRECTORY && resultCode != RESULT_CANCELED)
        {
            Bundle extras = intent.getExtras();
            String path;
            String key;
            File folder;
            String oldPath = null;

            if (extras == null)
            {
                Logger.debug("null extra: " + intent);
                return;
            }

            path = (String) extras.get(DirectoryPicker.CHOSEN_DIRECTORY);
            key = (String) extras.get(DirectoryPicker.AFFECTED_PREF);

            if (path == null || key == null)
            {
                Logger.debug("null path or key: " + intent);
                return;
            }

            folder = new File(path);

            if (!folder.exists())
                Toast.makeText(SettingsActivity.this, getString(R.string.pref_folder) + " " + path + " " + getString(R.string.pref_err_exists), Toast.LENGTH_SHORT).show();

            else if (!folder.canWrite())
                Toast.makeText(SettingsActivity.this, getString(R.string.pref_folder) + " " + path + " " + getString(R.string.pref_err_writable), Toast.LENGTH_SHORT).show();

            else if (!Shell.canExecuteInDir(folder.getAbsolutePath()) && !Shell.canRootExecuteInDir(Shell.getRealPath(folder.getAbsolutePath())))
                Toast.makeText(SettingsActivity.this, getString(R.string.pref_folder) + " " + path + " " + getString(R.string.pref_err_executable), Toast.LENGTH_LONG).show();

            else
            {
                //noinspection ConstantConditions
                getPreferenceManager().getSharedPreferences().edit().putString(key, path).commit();
                if (oldPath != null && !oldPath.equals(path))
                {
                    File current = new File(oldPath);

                    if (current.exists() && current.isDirectory() && current.listFiles().length > 2)
                    {
                        wipe_prompt_older(current);
                    }
                }
            }
        }
    }

    private void startDirectoryPicker(Preference preference)
    {
        Intent i = new Intent(SettingsActivity.this, DirectoryPicker.class);
        i.putExtra(DirectoryPicker.AFFECTED_PREF, preference.getKey());
        startActivityForResult(i, DirectoryPicker.PICK_DIRECTORY);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item)
    {
        switch (item.getItemId())
        {
            case android.R.id.home:
                onBackPressed();
                return true;

            default:
                return super.onOptionsItemSelected(item);
        }
    }

    @Override
    protected void onDestroy()
    {
        if (mReceiver != null)
        {
            unregisterReceiver(mReceiver);
            mReceiver = null;
        }
        super.onDestroy();
    }
}
