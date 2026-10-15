"""Compact, deterministic decision report. Full provenance remains in the sidecar."""
from io import BytesIO
from html import escape
from urllib.parse import urlparse
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, CondPageBreak
from reportlab.graphics.shapes import Drawing, Line, Circle, Polygon, String
from control_plan import priorities, priority_value, justification, selected_plan

RED = '#bc2835'
GREEN = '#14804a'


class ReadableTable(Table):
    """Keep ordinary rows intact; split only rows too tall for an entire page."""
    def split(self, availWidth, availHeight):
        self._calc(availWidth, availHeight)
        self.splitInRow = int(any(height > 730 - self._rowHeights[0] for height in self._rowHeights[1:]))
        return super().split(availWidth, availHeight)


def matrix_figure(payload, selected=None):
    import plotly.graph_objects as go
    ranked = {c['id']: str(i+1) for i,c in enumerate(priorities(payload))}
    points = [c for c in payload['components'] if c['assessment']['exposure'] is not None]
    figure = go.Figure()
    xs, ys = [], []
    for c in points:
        s=c['assessment']; xs.extend([s['impact'],s['impact'],None]); ys.extend([s['exposure'],s['residual'],None])
    figure.add_trace(go.Scatter(x=xs,y=ys,mode='lines',line=dict(color='#888888',width=1),showlegend=False,hoverinfo='skip'))
    for field,name,color,symbol,size in [('exposure','Before controls',RED,'circle',12),('residual','After controls (modeled)',GREEN,'diamond',7)]:
        figure.add_trace(go.Scatter(x=[c['assessment']['impact'] for c in points],y=[c['assessment'][field] for c in points],
            customdata=[c['id'] for c in points],name=name,mode='markers+text' if field=='exposure' else 'markers',
            text=[ranked.get(c['id'],'') for c in points] if field=='exposure' else None,textposition='top right',
            hovertext=[c['name']+f" · {c['assessment']['completeness']}% coverage" for c in points],
            hovertemplate='%{hovertext}<br>Impact %{x}<br>Exposure %{y}<extra>%{fullData.name}</extra>',
            marker=dict(size=size,symbol=symbol,color=color,opacity=.85,line=dict(width=[2 if c['id']==selected else 0 for c in points],color='#ffffff'))))
    figure.add_hline(y=50,line_color='#777777',line_dash='dot',opacity=.4)
    figure.add_vline(x=50,line_color='#777777',line_dash='dot',opacity=.4)
    figure.update_layout(height=420,margin=dict(l=20,r=20,t=20,b=20),paper_bgcolor='#0b0d0f',plot_bgcolor='#101316',
        font=dict(color='#e5e6e8'),legend=dict(orientation='h',y=-.2),
        xaxis=dict(title='MISSION IMPACT',range=[-3,105],gridcolor='#35383c'),
        yaxis=dict(title='EXPOSURE',range=[-3,105],gridcolor='#35383c'),clickmode='event+select')
    return figure


def matrix_drawing(payload):
    drawing=Drawing(511,270)
    left,bottom,width,height=42,43,450,200
    def point(s,field): return left+width*s['impact']/100,bottom+height*s[field]/100
    gray=colors.HexColor('#d7dce0')
    for tick in range(0,101,25):
        x=left+width*tick/100;y=bottom+height*tick/100
        drawing.add(Line(x,bottom,x,bottom+height,strokeColor=gray,strokeWidth=.5))
        drawing.add(Line(left,y,left+width,y,strokeColor=gray,strokeWidth=.5))
        drawing.add(String(x,bottom-13,str(tick),fontName='Helvetica',fontSize=7,textAnchor='middle'))
        drawing.add(String(left-7,y-2,str(tick),fontName='Helvetica',fontSize=7,textAnchor='end'))
    drawing.add(String(left+width/2,15,'MISSION IMPACT',fontSize=8,textAnchor='middle'))
    drawing.add(String(0,bottom+height+8,'EXPOSURE',fontSize=8))
    points=[c for c in payload['components'] if c['assessment']['exposure'] is not None]
    for c in points:
        x,y=point(c['assessment'],'exposure');_,after=point(c['assessment'],'residual')
        drawing.add(Line(x,y,x,after,strokeColor=colors.HexColor('#9ba3a8'),strokeWidth=.5))
    for c in points:
        x,y=point(c['assessment'],'exposure')
        drawing.add(Circle(x,y,3.6,fillColor=None,strokeColor=colors.HexColor(RED),strokeWidth=1.2))
    for c in points:
        x,y=point(c['assessment'],'residual')
        drawing.add(Polygon([x,y+2.4,x+2.4,y,x,y-2.4,x-2.4,y],fillColor=colors.HexColor(GREEN),strokeColor=colors.HexColor(GREEN)))
    placed=[]
    for rank,c in enumerate(priorities(payload),1):
        x,y=point(c['assessment'],'exposure')
        candidates=[(x+dx,y+dy) for dy in (8,-12,20,-24,32,-36) for dx in (7,-15,22,-30)]
        candidates=[(min(left+width-10,max(left+2,a)),min(bottom+height-8,max(bottom+2,b))) for a,b in candidates]
        a,b=next(((a,b) for a,b in candidates if all(abs(a-p)>12 or abs(b-q)>10 for p,q in placed)),candidates[-1])
        placed.append((a,b))
        drawing.add(Line(x,y,a,b,strokeColor=colors.HexColor('#888888'),strokeWidth=.4))
        drawing.add(String(a,b,str(rank),fontName='Helvetica-Bold',fontSize=8,fillColor=colors.HexColor('#222222')))
    return drawing


def pdf_report(payload):
    output=BytesIO()
    doc=SimpleDocTemplate(output,pagesize=(595.28,841.89),rightMargin=42,leftMargin=42,topMargin=34,bottomMargin=55,title='HEPHAESTUS assessment')
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Compact',fontName='Helvetica',fontSize=8,leading=10,spaceAfter=3,wordWrap='CJK'))
    styles.add(ParagraphStyle(name='Tiny',fontName='Helvetica',fontSize=7,leading=9,spaceAfter=3,wordWrap='CJK'))
    styles.add(ParagraphStyle(name='SectionNote',parent=styles['Tiny']))
    styles['Heading2'].fontSize=12;styles['Heading2'].spaceBefore=10;styles['Heading2'].spaceAfter=6
    styles['Heading2'].keepWithNext=False
    def clean(value): return escape(str(value)).replace('\n','<br/>')
    def p(value,style='Compact'): return Paragraph(clean(value),styles[style])
    def linked(label,url):
        if urlparse(str(url)).scheme not in ('http','https'): return clean(label)
        return f'<link href="{escape(str(url),quote=True)}" color="#225a88">{clean(label)}</link>'
    def table(rows,widths):
        table=ReadableTable(rows,colWidths=widths,repeatRows=1,hAlign='LEFT',splitInRow=1)
        table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e9edf0')),('VALIGN',(0,0),(-1,-1),'TOP'),
            ('LINEBELOW',(0,0),(-1,0),.6,colors.HexColor('#52616b')),('LINEBELOW',(0,1),(-1,-1),.3,colors.HexColor('#dce0e3')),
            ('LEFTPADDING',(0,0),(-1,-1),5),('RIGHTPADDING',(0,0),(-1,-1),5),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)]))
        return table
    def section(title,note,content):
        # Reserve the heading and first row, allowing the remaining rows to flow.
        first_height=30
        if isinstance(content,Table):
            content._calc(511,740)
            first_height=min(650,sum(content._rowHeights[:2]))
        story.extend([CondPageBreak(first_height+64),p(title,'Heading2'),p(note,'SectionNote'),content])
    unknown=sum(c['assessment']['exposure'] is None for c in payload['components'])
    synthetic=any('synthetic' in c.get('evidence',{}).get('mode','').lower() for c in payload['components'])
    story=[p('HEPHAESTUS','Title'),p('Generated '+payload['generated_at'][:19].replace('T',' ')+' UTC | '+str(len(payload['components']))+' components','Tiny')]
    if synthetic: story.append(p('SYNTHETIC EVIDENCE - illustrative scenario, not repository findings.'))
    else: story.append(p('Evidence mode: '+payload.get('source','Unknown')))
    story.extend([p('1. Mission exposure matrix','Heading2'),matrix_drawing(payload),
        Paragraph(f'<font color="{RED}">Red circles: before controls</font> | <font color="{GREEN}">Green diamonds: after controls (modeled)</font>',styles['Compact']),
        p(f'{unknown} component(s) with unknown exposure omitted from plot and ranking. Numbers match the priority table.','Tiny')])
    rows=[[p(x) for x in ('# / Component','Priority','Before / After','Coverage','Justification')]]
    for rank,c in enumerate(priorities(payload),1):
        result=c['assessment']
        name=f'{rank}. {c["name"]} / {c["version"]}'
        sources=[source['url'] for source in c.get('evidence',{}).get('sources',[]) if source.get('http_status')==200 and source.get('url')][:2]
        reason=clean(justification(c))
        if sources: reason+='<br/>'+' / '.join(linked('Source '+str(i+1),url) for i,url in enumerate(sources))
        rows.append([p(name),p(priority_value(result)),p(f'{result["exposure"]:g} / {result["residual"]:g}'),p(f'{result["completeness"]}%'),Paragraph(reason,styles['Compact'])])
    section('2. Ten highest-priority components',
        'Priority = mission impact x exposure before controls / 100. Higher values receive earlier review.',
        table(rows,[136,42,65,47,221]) if len(rows)>1 else p('No components have scored evidence yet.'))
    plan=selected_plan(payload)
    if not plan: content=p('No controls selected for implementation')
    else:
        rows=[[p('Selected action'),p('Applies to components')]]
        for item in plan:
            # Lists of Paragraphs allow long action/component cells to split across pages.
            actions=[Paragraph(linked(item['control'],item['source']),styles['Compact'])]
            actions += [p(action) for action in item['actions']]
            if item['modeled']: actions.append(p('Illustrative modeled reduction; verify effectiveness.','Tiny'))
            rows.append([actions,[p(label) for label in item['components']]])
        content=table(rows,[280,231])
    section('3. Selected implementation plan','Proposed, not verified implemented. Generated actions have no automatic score effect.',content)
    def footer(canvas,doc):
        canvas.setFont('Helvetica',7);canvas.setFillColor(colors.HexColor('#505c65'))
        canvas.drawString(42,34,'Ordinal prioritization; incomplete evidence may conceal exposure. Control effects are assumptions.')
        canvas.drawString(42,24,'Full evidence, sources, mission assignment and all drafts: accompanying JSON sidecar.')
        canvas.drawRightString(553,14,'HEPHAESTUS | '+str(doc.page))
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return output.getvalue()
