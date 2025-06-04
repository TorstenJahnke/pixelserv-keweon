/*
To create this header file do this:
1. Erstelle die index.html mit allen Infos
2. Nutze xxd zum erstellen der header Datei:
   xxd -i index.html > html_index.h
3. Compilen
4. Info zu template Dateien:
   - BLANK_HTML.template > eine simple HTML Datei ohne irgendwelche Zusätze, wird als *.html immer genommen
   - ZERO_HTML.template > eine komplett leere HTML Datei mit 0 bytes
*/

#ifndef HTML_INDEX_H
#define HTML_INDEX_H

unsigned char index_html[] = {};
unsigned int index_html_len = 0;

#endif // HTML_INDEX_H

