#-----------------------------------------------------------
# zusb
#   RegRipper Plugin
#   Display USB device info, actually and very likely the
#   first device connection. 
#   from __future__ import much much more! (ops, that's py!)
#
#   What about starting to collect info in the right
#   direction? fpi@LateNightCoding
#
#   *** WARNING *** POC *** WIP ***
#
# Change history
#
# References
#
# copyright "fpi" francesco.picasso@gmail.com
#-----------------------------------------------------------
package zusb;
use strict;

use Parse::Win32Registry qw( unpack_windows_time
                             unpack_unicode_string
                             unpack_sid
                             unpack_ace
                             unpack_acl
                             unpack_security_descriptor );

my %config = (hive          => "System",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20991332);

sub getConfig{return %config}

sub getShortDescr {
	return "Collects USB device infoz";
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching zusb v.".$VERSION);
    ::rptMsg("zusb v.".$VERSION);
    ::rptMsg("(".getHive().") ".getShortDescr()."\n");
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $current;
	my $ccs;
	my $key_path = 'Select';
	my $key;
    
	$key = $root_key->get_subkey($key_path);
    if (!$key) { ::rptMsg($key_path." not found."); return; }
    
    $current = $key->get_value("Current")->get_data();
	$ccs = "ControlSet00".$current;

	my $key_path = $ccs."\\Enum\\USB";
	my $key;
	$key = $root_key->get_subkey($key_path);
    if (!$key) { ::rptMsg($key_path." not found."); return; }
    	
    my @subkeys = $key->get_list_of_subkeys();
    ::rptMsg("Got ".scalar(@subkeys)." USB devices\n");
    if (!scalar(@subkeys)) { return; }
    foreach my $s (@subkeys)
    {
        my $tab = '';
        my $deviceID = $s->get_name();
        my $deviceID_rtime = gmtime($s->get_timestamp());
        ::rptMsg('');
        ::rptMsg('deviceID: '.$deviceID);
        ::rptMsg('deviceID registry last written: '.$deviceID_rtime);
        
        my @sk = $s->get_list_of_subkeys();
        ::rptMsg('got '.scalar(@sk).' instances');
        if (!scalar(@sk)) { next; }
        $tab = '  ';
        foreach my $k (@sk)
        {
            my $flag_install_failed = 0;
            my $instanceID = $k->get_name();
            my $instanceID_rtime = gmtime($k->get_timestamp());
            ::rptMsg($tab.'----------');
            ::rptMsg($tab.'instanceID: '.$instanceID);
            ::rptMsg($tab.'instanceID registry last written: '.$instanceID_rtime);
            
            my $class = $k->get_value("Class");
            if ($class) { $class = $class->get_data(); } else { $class = '<no value>'; }
            ::rptMsg($tab.'class: '.$class);
            
            my $service = $k->get_value("Service");
            if ($service) { $service = $service->get_data(); } else { $service = '<no value>'; }
            ::rptMsg($tab.'service: '.$service);
            
            my $driver = $k->get_value("Driver");
            if ($driver) { $driver = $driver->get_data(); } else { $driver = '<no value>'; $flag_install_failed = 1}
            ::rptMsg($tab.'driver: '.$driver);
            
            # Failed installation
            if ($flag_install_failed) { ::rptMsg($tab.'NOTE: device installation failed'); next; }
            
            my $propk = $k->get_subkey('Properties');
            if (!$propk) { ::rptMsg($tab.'Weird, missing Properties subkey!'); }
            else
            {
                my $bus_device_name = '<no data>';
                # devpkey.h
                # DEVPKEY_Device_BusReportedDeviceDesc {540b947e-8b40-45bc-a8a2-6a0b894cbda2},4
                my $bus_dev_name_key = $propk->get_subkey('{540b947e-8b40-45bc-a8a2-6a0b894cbda2}\\00000004\\00000000');
                if ($bus_dev_name_key)
                {
                    # devpropdef.h
                    # #define DEVPROP_TYPE_STRING 0x00000012  // null-terminated string
                    my $ptype = $bus_dev_name_key->get_value("Type");
                    my $pdata = $bus_dev_name_key->get_value("Data");
                    if ($ptype and $pdata)
                    {
                        if (unpack("V", $ptype->get_data()) == 0x00000012 ) {
                           $bus_device_name = unpack_unicode_string($pdata->get_data());
                        }
                    }
                }
                my $device_install_date = '<no data>';
                # devpkey.h
                # DEVPKEY_Device_InstallDate {83da6326-97a6-4088-9453-a1923f573b29}, 100
                # DEVPKEY_Device_FirstInstallDate {83da6326-97a6-4088-9453-a1923f573b29}, 101
                my $dev_install_date_key = $propk->get_subkey('{83da6326-97a6-4088-9453-a1923f573b29}\\00000064\\00000000');
                if ($dev_install_date_key)
                {
                    # devpropdef.h
                    # #define DEVPROP_TYPE_FILETIME 0x00000010  // file time (FILETIME)
                    my $ptype = $dev_install_date_key->get_value("Type");
                    my $pdata = $dev_install_date_key->get_value("Data");
                    if ($ptype and $pdata)
                    {
                        if (unpack("V", $ptype->get_data()) == 0x00000010 ) {
                           $device_install_date = unpack_windows_time($pdata->get_data());
                        }
                    }
                }
                my $device_first_install_date = '<no data>';
                # devpkey.h
                # DEVPKEY_Device_FirstInstallDate {83da6326-97a6-4088-9453-a1923f573b29}, 101
                my $dev_first_install_date_key = $propk->get_subkey('{83da6326-97a6-4088-9453-a1923f573b29}\\00000065\\00000000');
                if ($dev_first_install_date_key)
                {
                    # devpropdef.h
                    # #define DEVPROP_TYPE_FILETIME 0x00000010  // file time (FILETIME)
                    my $ptype = $dev_first_install_date_key->get_value("Type");
                    my $pdata = $dev_first_install_date_key->get_value("Data");
                    if ($ptype and $pdata)
                    {
                        if (unpack("V", $ptype->get_data()) == 0x00000010 ) {
                           $device_first_install_date = unpack_windows_time($pdata->get_data());
                        }
                    }
                }
                ::rptMsg($tab.'device name by BUS: '.$bus_device_name);
                ::rptMsg($tab.'device first install date: '.gmtime($device_first_install_date));
                ::rptMsg($tab.'device       install date: '.gmtime($device_install_date));
                
            }
        }
    }
}
1;