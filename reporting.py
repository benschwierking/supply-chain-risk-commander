"""Printable, provenance-aware assessment report. No network calls."""
from io import BytesIO
from html import escape
from urllib.parse import urlparse
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, CondPageBreak
from core import CONTROLS

def pdf_report(payload):
    output=BytesIO()
    doc=SimpleDocTemplate(output,pagesize=(595.28,841.89),rightMargin=42,leftMargin=42,topMargin=46,bottomMargin=46,title='HEPHAESTUS assessment')
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name='SmallBody',fontName='Helvetica',fontSize=8,leading=11,spaceAfter=6,wordWrap='CJK',allowWidows=0,allowOrphans=0))
    styles['BodyText'].fontSize=9
    styles['BodyText'].leading=13
    styles['BodyText'].allowWidows=0
    styles['BodyText'].allowOrphans=0
    styles['Heading1'].textColor=colors.HexColor('#9b252c')
    styles['Heading2'].spaceBefore=15
    story=[]
    def text(value):
        return escape(str(value)).replace('\n','<br/>')
    def p(value,style='BodyText'):
        return Paragraph(text(value),styles[style])
    def link(url,label=None):
        if urlparse(str(url)).scheme not in ('http','https'): return p(label or url,'SmallBody')
        return Paragraph(f'<link href="{escape(str(url),quote=True)}" color="#9b252c">{text(label or url)}</link>',styles['SmallBody'])
    def value(v): return 'Unknown' if v is None else str(v)
    def table(rows,widths):
        t=Table([[p(cell,'SmallBody') for cell in row] for row in rows],colWidths=widths,repeatRows=1,hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP'),('LINEBELOW',(0,0),(-1,0),.7,colors.HexColor('#9b252c')),('LINEBELOW',(0,1),(-1,-1),.3,colors.HexColor('#dddddd')),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6)]))
        return t
    story += [p('HEPHAESTUS','Title'),p('Component exposure assessment','Heading1'),p('Generated: '+payload['generated_at']),p('Evidence mode: '+payload['source']),p('SBOM SHA-256: '+payload.get('sbom_sha256','Unavailable'),'SmallBody'),Spacer(1,12)]
    story.append(p('Interpretation','Heading2'))
    story.extend(p(x) for x in payload['limitations'])
    story += [p('Method','Heading2'),p('Mission impact = 100 x (criticality + deployment reach + recovery difficulty) / 15. Each input is 1-5. Exposure = 100 x sum(weight x observed factor) / sum(known weights). Weights: concentration 30, archived 15, branch safeguard gap 30, review gap 25. Completeness is the sum of known weights, not statistical confidence. Residual uses selected illustrative reductions with the same denominator. Contributor web research is excluded from both scores and completeness.')]
    rows=[['Component / version','Impact','Exposure','Residual','Coverage']]
    for c in payload['components']:
        s=c['assessment'];rows.append([c['name']+' / '+c['version'],value(s['impact']),value(s['exposure']),value(s['residual']),str(s['completeness'])+'%'])
    story += [p('Inventory summary','Heading2'),table(rows,[235,60,70,70,76])]
    for c in payload['components']:
        s=c['assessment'];e=c.get('evidence',{})
        story += [CondPageBreak(360),p(c['name']+' / '+c['version'],'Heading1'),p('Inventory ID: '+c['id'],'SmallBody'),p('Evidence origin: '+e.get('mode','unknown')),p('Retrieved: '+str(e.get('fetched_at') or 'No live observation'),'SmallBody')]
        if c.get('repo'): story.append(link('https://github.com/'+c['repo']))
        story.append(p('Mission inputs: criticality {}, reach {}, recovery difficulty {} (each 1-5).'.format(*s['impact_inputs'])))
        story.append(p('Impact: {} | Exposure: {} | Modeled residual: {} | Completeness: {}%'.format(s['impact'],value(s['exposure']),value(s['residual']),s['completeness'])))
        story.append(p('Score drivers','Heading2'))
        rows=[['Driver','Observed (0-1)','Weight','Assumed reduction']]
        for d in s['drivers']: rows.append([d['factor'],d['observed'],d['weight'],str(round(d['modeled_reduction']*100))+'%'])
        story.append(table(rows,[190,100,80,141]) if len(rows)>1 else p('No scored observations; exposure is unknown.'))
        story.append(p('Proposed controls','Heading2'))
        for key in s['selected_controls']:
            title,control,factor,reduction=CONTROLS[key]
            story.append(p(f'{title} ({control}): assumed {reduction:.0%} reduction of {factor}. Not verified implementation.'))
        if not s['selected_controls']: story.append(p('None selected.'))
        story.append(link(payload['baseline'],'OSPS Baseline v2026.08.28'))
        for note in e.get('notes',[]): story.append(p(note,'SmallBody'))
        for source in e.get('sources',[]): story.append(link(source['url'],source['url']+' (HTTP '+str(source['http_status'])+')'))
        for person in e.get('contributors',[]):
            story.append(link(person.get('url',''),f"GitHub contributor {person.get('login','unknown')}: {person.get('contributions',0)} recorded contributions"))
        research_records=[r for r in payload.get('contributor_research',{}).values() if r.get('repository')==c.get('repo')]
        story.append(p('Contributor source research','Heading2'))
        if not research_records: story.append(p('Not run for this repository.'))
        for r in research_records:
            story.append(p(f"Status: {r.get('status')} | Retrieved: {r.get('retrieved_at')} | Searches attempted: {r.get('searches_attempted',0)}",'SmallBody'))
            story.append(p('Upstream revision: '+r.get('upstream_revision','unknown'),'SmallBody'))
            for note in r.get('limitations',[]): story.append(p(note,'SmallBody'))
            if r.get('error'): story.append(p(r['error']))
            for person in r.get('contributors',[]):
                story.append(p(person['login']+' - '+person['outcome'],'Heading3'))
                for q in person.get('queries',[]): story.append(p('Query: '+q,'SmallBody'))
                for err in person.get('errors',[]): story.append(p(err,'SmallBody'))
                for source in person.get('sources',[]):
                    story.append(link(source['url'],source['title']))
                    story.append(p(source['url'],'SmallBody'))
                    story.append(p('Heuristic match: '+source['heuristic_match']+'; human confirmation required.','SmallBody'))
                    story.append(p(source['excerpt'],'SmallBody'))
    story += [PageBreak(),p('Review and disposition','Heading1'),p('Verify repository mappings and missing safeguards before acceptance. Obtain mission-owner disposition; document an owner and expiry for exceptions. Selected controls are plans, not compliance evidence. Identity, nationality and U.S. Person status are unverified and require authorized attestation. Never infer them from names, language, location, or profile proxies.')]
    def footer(canvas,doc):
        canvas.setFont('Helvetica',8);canvas.setFillColor(colors.HexColor('#555555'));canvas.drawString(42,26,'HEPHAESTUS | Assessment report');canvas.drawRightString(553,26,str(doc.page))
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return output.getvalue()
