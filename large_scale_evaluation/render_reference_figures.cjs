/* Render published parameter sizes and an evidence-flow diagram.
 * No Python, experiment, key generation, or benchmark is executed here. */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sharp = require('sharp');
const { PDFDocument } = require('pdf-lib');
const base = __dirname;
const dir = path.join(base, 'figures');
fs.mkdirSync(dir, { recursive: true });
const escape = s => String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;');
const text = (x,y,s,size=23,weight='normal',color='#111',anchor='start') =>
  `<text x="${x}" y="${y}" font-size="${size}" font-weight="${weight}" fill="${color}" text-anchor="${anchor}">${escape(s)}</text>`;
const line = (x1,y1,x2,y2,color='#111',width=1.5,extra='') =>
  `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="${width}" ${extra}/>`;
const rect = (x,y,w,h,stroke='#111',fill='white',radius=0) =>
  `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${radius}" fill="${fill}" stroke="${stroke}" stroke-width="2"/>`;
const wrap = (w,h,body) => `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><rect width="100%" height="100%" fill="white"/><style>text{font-family:'Times New Roman';}</style><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0 L8 4 L0 8" fill="#111"/></marker><marker id="redArrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0 L8 4 L0 8" fill="#a32020"/></marker></defs>${body}</svg>`;
const sources = fs.readFileSync(path.join(base,'baseline_parameters.csv'),'utf8');
const rows = sources.trim().split(/\r?\n/).slice(1).map(s=>s.split(','));
let chart = text(42,44,'Post-quantum KEM parameter sizes',32,'bold');
chart += text(42,77,'Five category 3 parameter sets; specification values',23);
const W=1320,H=690;
const panels=[{start:405,width:365,title:'Public key',field:3},{start:900,width:365,title:'KEM ciphertext',field:4}];
for(const p of panels){
  chart += text(p.start,126,p.title,26,'bold');
  for(let exponent=2;exponent<=6;exponent++){
    const x=p.start+(exponent-2)/4*p.width;
    chart += line(x,145,x,566,'#d0d0d0',1);
    chart += text(x,599,({2:'100',3:'1,000',4:'10,000',5:'100,000',6:'1,000,000'})[exponent],18,'normal','#111','middle');
  }
  chart += line(p.start,566,p.start+p.width,566);
}
rows.forEach((r,i)=>{
  const y=184+i*78;
  const color=i===0?'#a32020':'#111';
  const display=r[0]==='FrodoKEM-976-SHAKE'?'FrodoKEM-976-SHAKE':r[0];
  chart += text(42,y+8,display,23,i===0?'bold':'normal',color);
  for(const p of panels){
    const value=Number(r[p.field]);
    const width=(Math.log10(value)-2)/4*p.width;
    chart += `<rect x="${p.start}" y="${y-15}" width="${width}" height="28" fill="${p.field===3?'white':color}" stroke="${color}" stroke-width="2"/>`;
    // Place the value beyond short bars and inside the reserved right margin.
    chart += text(p.start+width+10,y+7,value.toLocaleString('en-US'),21,'normal',color,'start');
  }
});
chart += text(835,634,'Size in bytes (logarithmic axes)',23,'normal','#111','middle');
chart += text(42,671,'Red: ML-KEM used by LA-IoT. Source: Open Quantum Safe parameter datasheets.',20);

let flow=text(38,43,'From execution evidence to reported results',31,'bold');
flow+=text(38,76,'Each artifact shares a run identifier and a recorded hash',23);
const top=[
  {x:38,t:'20-device configuration',a:'Pico sensing and firmware',b:'Pi / Nano process records'},
  {x:461,t:'Cryptographic profiles',a:'KEM + BFV processing',b:'Sizes, time, host memory'},
  {x:884,t:'Cooja network model',a:'Saved topology and seed',b:'Frames, queues, delivery'}
];
for(const b of top){
  flow+=rect(b.x,108,398,123);
  flow+=text(b.x+199,142,b.t,25,'bold','#111','middle');
  flow+=text(b.x+199,177,b.a,23,'normal','#111','middle');
  flow+=text(b.x+199,209,b.b,23,'normal','#111','middle');
  flow+=line(b.x+199,231,b.x+199,272,'#111',2);
}
flow+=line(237,272,1083,272,'#111',2);
flow+=line(660,272,660,309,'#a32020',3,'marker-end="url(#redArrow)"');
flow+=rect(240,311,840,103,'#a32020');
flow+=text(660,347,'Matched inputs, configurations, logs and calibration',25,'bold','#a32020','middle');
flow+=text(660,384,'Run ID + placement + clock domain + SHA-256',23,'normal','#111','middle');
flow+=line(660,414,660,452,'#a32020',3,'marker-end="url(#redArrow)"');
flow+=line(237,456,1083,456,'#111',2);
const bottom=[
  {x:38,t:'Performance',a:'JCT, latency, completion',b:'All transmitted frames'},
  {x:461,t:'Energy',a:'Measured board power',b:'Modeled network states'},
  {x:884,t:'Security and recovery',a:'Tampering, replay, missing',b:'Exact bytes and statistics'}
];
for(const b of bottom){
  flow+=line(b.x+199,456,b.x+199,484,'#111',2,'marker-end="url(#arrow)"');
  flow+=rect(b.x,486,398,125);
  flow+=text(b.x+199,520,b.t,25,'bold','#111','middle');
  flow+=text(b.x+199,555,b.a,23,'normal','#111','middle');
  flow+=text(b.x+199,589,b.b,23,'normal','#111','middle');
}
flow+=text(38,654,'Independent runs provide confidence intervals; missing measurements remain unreported.',22);

async function save(name,width,height,body){
  const svg=wrap(width,height,body);
  fs.writeFileSync(path.join(dir,`${name}.svg`),svg);
  const png=await sharp(Buffer.from(svg),{density:300}).png().toBuffer();
  fs.writeFileSync(path.join(dir,`${name}.png`),png);
  const pdf=await PDFDocument.create();
  const img=await pdf.embedPng(png);
  const page=pdf.addPage([width*0.43,height*0.43]);
  page.drawImage(img,{x:0,y:0,width:width*0.43,height:height*0.43});
  pdf.setTitle(name==='pqc_parameter_sizes'?'Published KEM parameter sizes':'Evaluation evidence flow');
  pdf.setSubject('No experimental performance values are generated.');
  fs.writeFileSync(path.join(dir,`${name}.pdf`),await pdf.save());
}
(async()=>{
  await save('pqc_parameter_sizes',W,H,chart);
  await save('evaluation_evidence_flow',1320,675,flow);
  const manifest={kind:'published_parameters_and_method_diagram',experimental_results:false,font:'Times New Roman',parameter_csv_sha256:crypto.createHash('sha256').update(sources).digest('hex'),script_sha256:crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),sources:rows.map(r=>({algorithm:r[0],url:r[7]}))};
  fs.writeFileSync(path.join(dir,'figure_provenance.json'),JSON.stringify(manifest,null,2)+'\n');
})();

