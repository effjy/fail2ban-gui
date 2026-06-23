CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
GTK_CF   = `pkg-config --cflags gtk4`
GTK_LIB  = `pkg-config --libs gtk4`

BIN      = fail2ban-gui
SRC      = src/gui.cpp src/tray.cpp src/helper.cpp
HDR      = src/tray.h src/helper.h

PREFIX   = /usr/local
BINDIR   = $(PREFIX)/bin
APPDIR   = /usr/share/applications
ICONDIR  = /usr/share/icons/hicolor/256x256/apps
SVGDIR   = /usr/share/icons/hicolor/scalable/apps

all: $(BIN)

$(BIN): $(SRC) $(HDR)
	$(CXX) $(CXXFLAGS) $(GTK_CF) -o $@ $(SRC) $(GTK_LIB)

clean:
	rm -f $(BIN)

install: all
	@echo "Installing binary..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

	@echo "Installing desktop entry and icons..."
	install -d $(DESTDIR)$(APPDIR) $(DESTDIR)$(ICONDIR) $(DESTDIR)$(SVGDIR)
	install -m 0644 fail2ban-gui.desktop   $(DESTDIR)$(APPDIR)/fail2ban-gui.desktop
	install -m 0644 icons/fail2ban-gui.png $(DESTDIR)$(ICONDIR)/fail2ban-gui.png
	install -m 0644 icons/fail2ban-gui.svg $(DESTDIR)$(SVGDIR)/fail2ban-gui.svg

	-gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	@echo
	@echo "Installed. Launch 'Fail2ban GUI' from your menu (or run 'fail2ban-gui')."
	@echo "It will ask once via pkexec for the privileges fail2ban-client needs."

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(APPDIR)/fail2ban-gui.desktop
	rm -f $(DESTDIR)$(ICONDIR)/fail2ban-gui.png
	rm -f $(DESTDIR)$(SVGDIR)/fail2ban-gui.svg
	-gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	@echo "Uninstalled."

.PHONY: all clean install uninstall
