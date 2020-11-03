package com.knetapp.systray;

import java.awt.Dimension;
import java.awt.Image;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.Toolkit;
import java.awt.TrayIcon;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.imageio.ImageIO;
import javax.swing.JOptionPane;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.knetapp.service.nfeServerPublisher;

public class nfeSystemTray {

static Logger logger = LoggerFactory.getLogger(nfeSystemTray.class);	
static String appdata = System.getenv("APPDATA").replace("\\","\\\\");

public static void main(String[] args) throws Exception {
			
			logger.info("Start Service.....");
			
			logger.warn("Create registry windows...");
			create_registry();
			logger.info("waiting 1 seconds....");
			
			Thread.sleep(3000);
			logger.info("Registry app wvetro");
			execute_registry();
			
			Thread.sleep(3000);
			
		    if (!SystemTray.isSupported()) {			
				logger.error("SystemTray is not supported");
				return;
			} else {
				
			String code = urlaccess();
		
			
			if (code.equals("Service offline")) {
			  nfeServerPublisher server = new nfeServerPublisher();
			  server.main();
			}
			
			SystemTray tray = SystemTray.getSystemTray();
			@SuppressWarnings("unused")
			Toolkit toolkit = Toolkit.getDefaultToolkit();
			Dimension trayIconSize = tray.getTrayIconSize();

			File folderInput = new File("resource//icon.png");
			Image image = ImageIO.read(folderInput);
			image = image.getScaledInstance(trayIconSize.width, trayIconSize.height, Image.SCALE_SMOOTH);
			
			PopupMenu menu = new PopupMenu();

			MenuItem messageItem = new MenuItem("Version");
			
			messageItem.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					JOptionPane.showMessageDialog(null, "1.0.0");
				}
			});

			menu.add(messageItem);

			MenuItem closeItem = new MenuItem("Sair");
			closeItem.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					System.exit(0);
				}
			});

			menu.add(closeItem);

			TrayIcon icon = new TrayIcon(image, "Service SmartCard.", menu);
			tray.add(icon);
			
		}
	}

	@SuppressWarnings("static-access")
	private static void execute_registry() {
		
		String fileexecute = System.getenv("APPDATA") + "\\wvetro\\" + "wvetro.reg"; 
		fileexecute = fileexecute.format("cmd.exe /c REG IMPORT %s","\""+ fileexecute+ "\"");

		Process process = null;
		try {
			process = Runtime.getRuntime().exec(fileexecute);
			process.waitFor();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void create_registry() {
		
		StringBuilder registry = new StringBuilder();
		registry.append("Windows Registry Editor Version 5.00")
			 .append("\n\n") 
	    	 .append("[HKEY_CURRENT_USER\\SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\com.knetapp.native]")
	    	 .append("\n") 
	    	 .append("@=\"")
	    	 .append(appdata)
	    	 .append("\\\\wvetro\\\\com.knetapp.native.json\"");
		
		StringBuffer str = new StringBuffer();
		str.append(registry);

		try {

			FileWriter out = new FileWriter(appdata+ "\\\\wvetro\\\\wvetro.reg");
			out.write(str.toString());
			out.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static String urlaccess() {    
		    
		int responseCode = 0;
		String retorno   = null;

		try {
			URL url = new URL("http://127.0.0.1:9876/com.knetapp.service.ServiceServer");
			HttpURLConnection huc = (HttpURLConnection) url.openConnection();
			responseCode = huc.getResponseCode();
		} catch (Exception e) {
			logger.equals("error loading " + e.getMessage());
		}

		if (responseCode == 200) {
			retorno = "Service online";
		} else {
			retorno = "Service offline";
		}
		    
		return retorno;
	}
	
	
}