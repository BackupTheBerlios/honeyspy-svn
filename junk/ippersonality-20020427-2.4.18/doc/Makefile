DOC	= ippersonality
FRFLAGS	= -v -l fr -D lang=fr -p a4 -c latin
ENFLAGS	= -v -l en -D lang=en -p letter -c latin
TEMP	= $(DOC)-fr.sgml $(DOC)-en.sgml
ALL	= $(DOC)-fr.html $(DOC)-en.html $(DOC)-fr.txt $(DOC)-en.txt

all: $(ALL)
	rm -f $(TEMP)

%-fr.sgml: %.sgml
	sed "s,<\(fr\|en\)>,<#if lang=\1>,g;s,</\(fr\|en\)>,</#if>,g;" < $< > $@

%-en.sgml: %-fr.sgml
	ln -s $< $@

%-fr.html: %-fr.sgml
	sgml2html $(FRFLAGS) $<

%-en.html: %-en.sgml
	sgml2html $(ENFLAGS) $<

%-fr.txt: %-fr.sgml
	sgml2txt $(FRFLAGS) $<

%-en.txt: %-en.sgml
	sgml2txt $(ENFLAGS) $<

clean:
	rm -f $(DOC)*.html $(DOC)*.txt $(TEMP)
