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
package it.evilsocket.dsploit;

import android.app.Application;

import it.evilsocket.dsploit.core.System;
import it.evilsocket.dsploit.plugins.Inspector;
import it.evilsocket.dsploit.plugins.PortScanner;
import it.evilsocket.dsploit.plugins.Traceroute;

public class DSploitApplication extends Application
{
    @Override
    public void onCreate()
    {
        setTheme(R.style.AppTheme);

        super.onCreate();

        // initialize the system
        try
        {
            System.init(this);
        }
        catch (Exception e)
        {
            System.errorLogging(e);

            // ignore exception when the user has wifi off
            //if (!(e instanceof NoRouteToHostException))
                //BugSenseHandler.sendException(e);
        }

        // load system modules even if the initialization failed
        System.registerPlugin(new Traceroute());
        System.registerPlugin(new PortScanner());
        System.registerPlugin(new Inspector());

    }
}
