"""Explicit exports from stored analysis results."""
import json
import re
import os
import uuid
from datetime import datetime
from pathlib import Path
import pandas as pd
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.worksheet.table import Table, TableStyleInfo
from .engine import slug


def filename(organization, run_id, suffix):
    return f'{slug(organization)}_run_{run_id}_{datetime.now():%Y%m%d_%H%M%S}.{suffix}'


OPTIONS = ('Export EASM Assets', 'Export Verified Results', 'Export Candidates',
           'Export Rejected', 'Export Evidence', 'Export Full Workbook')


def export_results(rows, destination, mode=None, organization=None, overwrite=False, metadata=None):
    from .credentials import sanitize
    rows = sanitize(rows)
    if organization is not None:
        rows = [row for row in rows if row['organization'].casefold() == organization.casefold()]
    path = Path(destination)
    if path.exists() and not overwrite:
        raise FileExistsError('Choose Replace or another filename before exporting.')
    if mode not in (None, *OPTIONS):
        raise ValueError('Unknown export option')
    if mode in ('Export EASM Assets', 'Export Verified Results'):
        rows = [row for row in rows if row['included']]
    elif mode == 'Export Rejected':
        rows = [row for row in rows if not row['included'] and row['status'] != 'PENDING']
    path.parent.mkdir(parents=True,exist_ok=True)
    working=path.with_name(f'.{path.stem}.{uuid.uuid4().hex}.tmp{path.suffix}')
    metadata = metadata or {}
    payload = []
    evidence = []
    breakdown = []
    for row in rows:
        finding = row['finding']
        candidate = row.get('candidate', {}); observations = finding.get('evidence', []) or []
        sources = '; '.join(dict.fromkeys(str(source) for source,_,_ in observations))
        summary = '\n'.join(f'{source}: {detail}' for source,detail,_ in observations)
        owner = finding.get('registered_org') or finding.get('origin_org') or candidate.get('origin_organization') or ''
        payload.append({
            'Organization': row['organization'], 'Target Entity': row['entity'],
            'Target Domain': '; '.join(row.get('domains', [])), 'IP Address': row['ip'],
            'Hostname': row.get('hostname',''), 'Current ASN': finding.get('origin_asn') or candidate.get('origin_asn',''),
            'ASN Organization': finding.get('origin_org') or candidate.get('origin_organization',''),
            'Infrastructure Owner': owner, 'Target Association': row['organization'],
            'Relationship': finding.get('relationship',''), 'Attribution Classification': row['status'],
            'Confidence': finding.get('confidence',''), 'Score': finding.get('score',''),
            'Included in EASM': 'Yes' if row['included'] else 'No',
            'Primary Evidence': next((d for _,d,p in observations if p>0),''), 'Evidence Summary': summary,
            'Attribution Reason': finding.get('proof',''),
            'Discovery Source': '; '.join(candidate.get('discovery_sources',[])), 'Verification Sources': sources,
            'TLS Evidence': '\n'.join(d for s,d,_ in observations if s=='TLS'),
            'DNS Evidence': '\n'.join(d for s,d,_ in observations if s=='DNS'),
            'Registration Evidence': '\n'.join(d for s,d,_ in observations if s=='RDAP'),
            'Routing Evidence': '\n'.join(d for s,d,_ in observations if s in ('BGP','RIPEstat','ASN')),
            'Shared Infrastructure': 'Yes' if row['status']=='SHARED_INFRASTRUCTURE' else 'No',
            'First Observed': candidate.get('first_seen',''), 'Last Verified': metadata.get('completed',''),
            'Analysis Date': metadata.get('started',''),
        })
        for source, detail, points in observations:
            impact='Supports association' if points>0 else 'Cautionary evidence' if points<0 else 'Context only'
            item={'Organization':row['organization'],'Target Entity':row['entity'],'IP Address':row['ip'],
                  'Hostname':row.get('hostname',''),'Evidence Family':source,'Evidence Type':source,
                  'Observation':detail,'Points':points,'Impact':impact,'Source / Provider':source,
                  'Analysis ID':metadata.get('id','')}
            evidence.append(item)
            breakdown.append({**{k:item[k] for k in ('IP Address','Hostname','Evidence Family','Evidence Type','Observation','Points','Impact')},
                              'Final Score':finding.get('score',''),'Classification':row['status']})
    if path.suffix.lower() == '.json':
        json_payload=[{**row,'Proof Summary':row.get('Attribution Reason','')} for row in payload]
        working.write_text(json.dumps({'results': json_payload, 'evidence': evidence}, indent=2, default=str), encoding='utf-8')
        _publish(working,path,overwrite)
    else:
        columns=list(payload[0]) if payload else ['Organization','Target Entity','Target Domain','IP Address','Hostname','Current ASN',
            'ASN Organization','Infrastructure Owner','Target Association','Relationship','Attribution Classification','Confidence',
            'Score','Included in EASM','Primary Evidence','Evidence Summary','Attribution Reason','Discovery Source','Verification Sources',
            'TLS Evidence','DNS Evidence','Registration Evidence','Routing Evidence','Shared Infrastructure','First Observed','Last Verified','Analysis Date']
        frame=pd.DataFrame(payload,columns=columns)
        verified=frame[frame['Included in EASM']=='Yes']
        rejected=frame[(frame['Included in EASM']=='No') & (frame['Attribution Classification']!='PENDING')]
        candidate_rows=[]
        rejection_rows=[]
        for row in rows:
            candidate=row.get('candidate',{}); finding=row['finding']; origin=finding.get('origin_asn') or candidate.get('origin_asn','')
            candidate_rows.append({'Organization':row['organization'],'Target Entity':row['entity'],
                'Target Domain':'; '.join(row.get('domains',[])),'Candidate IP':row['ip'],'Hostname':row.get('hostname',''),
                'Current ASN':origin,'ASN Organization':finding.get('origin_org') or candidate.get('origin_organization',''),
                'Discovery Source':'; '.join(candidate.get('discovery_sources',[])),
                'Discovery Evidence':str(candidate.get('discovery_evidence','')),'Verification Status':row['status'],
                'Current Score':finding.get('score',''),'Classification':row['status'],
                'Infrastructure Type':candidate.get('hosting_provider',''),'Infrastructure Owner':finding.get('registered_org') or finding.get('origin_org') or '',
                'Shared Provider': 'Yes' if row['status']=='SHARED_INFRASTRUCTURE' else 'No',
                'Included in EASM':'Yes' if row['included'] else 'No','Exclusion Reason':finding.get('proof','') if not row['included'] else '',
                'Evidence Count':len(finding.get('evidence',[])),'Last Checked':metadata.get('completed','')})
            if not row['included'] and row['status']!='PENDING':
                targets=[t for t in metadata.get('targets',[]) if t['parent_organization'].casefold()==row['organization'].casefold() and t['target_entity']==row['entity']]
                known=origin if any(origin in t.get('known_asns',[]) for t in targets) else ''
                reason=finding.get('proof') or ('Current origin ASN matches a known target ASN; not an off-ASN candidate.' if known else 'Insufficient evidence for inclusion.')
                rejection_rows.append({'Organization':row['organization'],'Target Entity':row['entity'],
                    'Domain':'; '.join(row.get('domains',[])),'IP Address':row['ip'],'Current ASN':origin,
                    'ASN Organization':finding.get('origin_org') or candidate.get('origin_organization',''),
                    'Discovery Source':'; '.join(candidate.get('discovery_sources',[])),'Score':finding.get('score',''),
                    'Classification':row['status'],'Rejected Because':reason,
                    'Evidence Summary':'\n'.join(f'{s}: {d}' for s,d,_ in finding.get('evidence',[])),
                    'Observed ASN':origin,'Known Target ASN':known,'Last Checked':metadata.get('completed','')})
        candidates=pd.DataFrame(candidate_rows)
        rejected_report=pd.DataFrame(rejection_rows,columns=['Organization','Target Entity','Domain','IP Address','Current ASN',
            'ASN Organization','Discovery Source','Score','Classification','Rejected Because','Evidence Summary',
            'Observed ASN','Known Target ASN','Last Checked'])
        evidence_columns=['Organization','Target Entity','IP Address','Hostname','Evidence Family','Evidence Type','Observation',
                          'Points','Impact','Source / Provider','Analysis ID']
        observations=pd.DataFrame(evidence,columns=evidence_columns)
        score_breakdown=pd.DataFrame(breakdown,columns=['IP Address','Hostname','Evidence Family','Evidence Type','Observation',
            'Points','Impact','Final Score','Classification'])
        with pd.ExcelWriter(working,engine='openpyxl') as writer:
            if mode=='Export EASM Assets': verified.to_excel(writer,sheet_name='EASM Assets',index=False)
            elif mode=='Export Verified Results': verified.to_excel(writer,sheet_name='Verified Results',index=False)
            elif mode=='Export Candidates': candidates.to_excel(writer,sheet_name='Candidates',index=False)
            elif mode=='Export Rejected': rejected_report.to_excel(writer,sheet_name='Rejected',index=False)
            elif mode=='Export Evidence': observations.to_excel(writer,sheet_name='Evidence',index=False)
            else:
                statuses=frame['Attribution Classification'] if not frame.empty else pd.Series(dtype=str)
                summary={'Organization':organization or metadata.get('organization',''),
                    'Target Entities':'; '.join(t['target_entity'] for t in metadata.get('targets',[])),
                    'Target Domains':'; '.join(dict.fromkeys(d for t in metadata.get('targets',[]) for d in t.get('target_domains',[]))),
                    'Known Target ASNs':'; '.join(dict.fromkeys(a for t in metadata.get('targets',[]) for a in t.get('known_asns',[]))),
                    'Analysis Date':metadata.get('started',''),'Analysis ID':metadata.get('id',''),
                    'Analysis Status':metadata.get('status',''),'Total Hostnames Discovered':len({h for r in rows for h in r.get('hostname','').split(';') if h}),
                    'Total IPv4 Candidates':len(rows),'Known-ASN Rejections':sum(r['status']=='KNOWN_ASN_EXCLUDED' for r in rows),
                    'Verified Assets':len(verified),'Confirmed Owned':sum(statuses=='CONFIRMED_OWNED'),
                    'Confirmed Leased':sum(statuses=='CONFIRMED_LEASED'),'Confirmed Operated':sum(statuses=='CONFIRMED_OPERATED'),
                    'Likely Associated':sum(statuses=='LIKELY_ASSOCIATED'),'Shared Infrastructure':sum(statuses=='SHARED_INFRASTRUCTURE'),
                    'Unverified':sum(statuses.isin(['UNVERIFIED','ERROR'])),'Rejected':len(rejected_report)}
                pd.DataFrame([summary]).to_excel(writer,sheet_name='Summary',index=False)
                verified.to_excel(writer,sheet_name='EASM Assets',index=False)
                candidates.to_excel(writer,sheet_name='Candidates',index=False)
                rejected_report.to_excel(writer,sheet_name='Rejected',index=False)
                observations.to_excel(writer,sheet_name='Evidence',index=False)
                score_breakdown.to_excel(writer,sheet_name='Score Breakdown',index=False)
                _score_guide().to_excel(writer,sheet_name='Score Guide',index=False)
        _format_workbook(working)
        _publish(working,path,overwrite)
    return path


def _publish(working,path,overwrite):
    try:
        if overwrite: os.replace(working,path)
        else: os.link(working,path)
    finally:
        if working.exists(): working.unlink()


def _score_guide():
    from .engine import config
    threshold=config().get('confidence_thresholds',{'confirmed':90,'high':75,'medium':50,'low':30})
    bands=[('UNVERIFIED',0,threshold['low']-1),('LOW',threshold['low'],threshold['medium']-1),
           ('MEDIUM',threshold['medium'],threshold['high']-1),('HIGH',threshold['high'],threshold['confirmed']-1),
           ('CONFIRMED',threshold['confirmed'],100)]
    rows=[]
    for name,low,high in bands:
        if low>high: continue
        interpretations={'UNVERIFIED':'UNVERIFIED or SHARED_INFRASTRUCTURE',
            'LOW':'UNVERIFIED or SHARED_INFRASTRUCTURE',
            'MEDIUM':'LIKELY_ASSOCIATED unless shared infrastructure applies',
            'HIGH':'CONFIRMED_LEASED or CONFIRMED_OPERATED only with the required relationship; otherwise review',
            'CONFIRMED':'CONFIRMED_OWNED only with Owned relationship; lease/operation follow their respective rules'}
        rows.append({'Score / Range':f'{low}–{high}','Meaning':f'{name} confidence band from configured thresholds',
            'Typical Interpretation':'An evidence indicator; read with the recorded relationship and proof.',
            'Possible Classification':interpretations[name],
            'EASM Inclusion Behavior':'Score alone never proves ownership or causes inclusion.',
            'Evidence Rules':'DNS +25; matching TLS +25; Censys historical DNS +20; target PTR +15; Shodan association +10; matching RDAP +10; official material +20; shared names −20; unrelated RDAP −30. CT context scores 0.'})
    rows.append({'Score / Range':'0–100, clamped','Meaning':'Evidence/confidence indicator, not proof of IP ownership.',
        'Typical Interpretation':'Strong target association does not automatically mean the target owns the IP.',
        'Possible Classification':'Classification also depends on recorded relationship and independent evidence.',
        'EASM Inclusion Behavior':'Only CONFIRMED_OWNED, CONFIRMED_LEASED and CONFIRMED_OPERATED are included.',
        'Evidence Rules':'Read the Evidence and Score Breakdown sheets; zero-point context is not proof.'})
    return pd.DataFrame(rows)


def _format_workbook(path):
    from openpyxl import load_workbook
    from openpyxl.utils import get_column_letter
    workbook=load_workbook(path)
    header_fill=PatternFill('solid',fgColor='243A55'); hairline=Side(style='hair',color='E1E6EC')
    for sheet in workbook.worksheets:
        sheet.freeze_panes='A2'; sheet.sheet_view.showGridLines=False; sheet.sheet_view.zoomScale=90
        sheet.auto_filter.ref=sheet.dimensions
        headers={cell.column:cell.value for cell in sheet[1]}
        for cell in sheet[1]:
            cell.fill=header_fill; cell.font=Font(name='Aptos',size=10,bold=True,color='FFFFFF')
            cell.alignment=Alignment(vertical='center',wrap_text=True)
        sheet.row_dimensions[1].height=32
        for column,title in headers.items():
            name=str(title).lower()
            width={'ip address':17,'ip':17,'current asn':13,'observed asn':13,'known target asn':16,'score':10,'points':9,
                'included in easm':16,'organization':25,'target entity':22,'target domain':25,'domain':25,'hostname':28,
                'infrastructure owner':26,'asn organization':24,'attribution classification':28,'classification':27,
                'relationship':22,'confidence':14,'evidence family':20,'evidence type':21,'impact':22}.get(name,
                44 if any(x in name for x in ('observation','summary','reason','evidence','meaning','interpretation','rules')) else 19)
            sheet.column_dimensions[get_column_letter(column)].width=width
        for row in sheet.iter_rows(min_row=2):
            sheet.row_dimensions[row[0].row].height=34
            for cell in row:
                cell.font=Font(name='Aptos',size=10,color='263446')
                cell.alignment=Alignment(vertical='top',wrap_text=True)
                cell.border=Border(bottom=hairline)
                header=str(headers.get(cell.column,'')).lower()
                if header in ('points','score','final score','score / range','included in easm'):
                    cell.alignment=Alignment(horizontal='center',vertical='center',wrap_text=True)
                if header in ('attribution classification','classification'):
                    shade={'CONFIRMED_OWNED':'E6F2EA','CONFIRMED_LEASED':'E6F2EA','CONFIRMED_OPERATED':'E6F2EA',
                        'LIKELY_ASSOCIATED':'FFF3D8','SHARED_INFRASTRUCTURE':'E8EDF3','KNOWN_ASN_EXCLUDED':'F1E9EA',
                        'UNVERIFIED':'F1E9EA','ERROR':'FBE5E5'}.get(str(cell.value or ''))
                    if shade: cell.fill=PatternFill('solid',fgColor=shade)
        if sheet.max_row>=2 and sheet.max_column:
            table_name=re.sub('[^A-Za-z0-9]','',sheet.title)[:20]+'Data'
            table=Table(displayName=table_name,ref=f'A1:{get_column_letter(sheet.max_column)}{sheet.max_row}')
            table.tableStyleInfo=TableStyleInfo(name='TableStyleMedium2',showFirstColumn=False,showLastColumn=False,
                                                showRowStripes=True,showColumnStripes=False)
            sheet.add_table(table)
    workbook.save(path)
