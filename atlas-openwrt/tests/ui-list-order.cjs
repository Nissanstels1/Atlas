'use strict';
const fs=require('fs'),path=require('path'),assert=require('assert/strict');
const source=fs.readFileSync(path.join(__dirname,'../root/www/luci-static/resources/view/atlas/overview.js'),'utf8');
const merge=new Function(source.slice(source.indexOf('function atlasElement'),source.indexOf('return view.extend({'))+'return atlasMergeSectionLists;')();
const row=(id,section,name=id)=>({id,section,name,url:'https://example.org/'+id,policy:'proxy',enabled:true});
const ids=rows=>rows.map(item=>item.id);

// YouTube's specific rule must stay ahead of a broad Russia list after an
// unrelated section-name/profile edit that returns unchanged source rows.
const original=[row('youtube','video'),row('russia_inside','main'),row('google_ai','main'),row('global','')];
let result=merge(original,{video:[{...original[0],name:'YouTube renamed'}]});
assert.deepEqual(ids(result),ids(original));
assert.equal(result[0].name,'YouTube renamed');
assert.equal(result[1].name,'russia_inside');

// The order of editing sections must not become the routing priority. Even
// reversed override arrays preserve the positions of already-existing IDs.
result=merge(original,{
 main:[{...original[2],enabled:false},{...original[1],name:'Russia renamed'}],
 video:[{...original[0],name:'Video renamed'}]
});
assert.deepEqual(ids(result),ids(original));
assert.equal(result[0].name,'Video renamed');
assert.equal(result[1].name,'Russia renamed');
assert.equal(result[2].enabled,false);

// Deleted entries disappear. Additions follow the last old list of their own
// section; interleaved foreign/global rules preserve their relative order.
const interleaved=[row('v1','video'),row('m1','main'),row('global',''),row('v2','video'),row('m2','main'),row('tail','other')];
result=merge(interleaved,{video:[row('v2','video','Updated'),row('v3','video'),row('v4','video')]});
assert.deepEqual(ids(result),['m1','global','v2','v3','v4','m2','tail']);
assert.equal(result[2].name,'Updated');
result=merge(interleaved,{video:[]});
assert.deepEqual(ids(result),['m1','global','m2','tail']);
result=merge(interleaved,{video:[row('replacement','video')]});
assert.deepEqual(ids(result),['m1','global','replacement','m2','tail']);

// New sections have no existing anchor, so only their own new rows append.
result=merge(original,{new_section:[row('new1','new_section'),row('new2','new_section')],main:[...original.slice(1,3),row('main_new','main')]});
assert.deepEqual(ids(result),['youtube','russia_inside','google_ai','main_new','global','new1','new2']);
assert.deepEqual(merge([],{}),[]);
assert.deepEqual(ids(merge([],{new_section:[row('first','new_section')]})),['first']);

// A pure merge never edits the incoming arrays/records. Returned flat source
// records are copies because the save path attaches permissions afterwards.
function freeze(value){if(value && typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;}
const frozenLists=freeze(original.map(item=>({...item}))),frozenOverrides=freeze({video:[{...original[0],name:'Frozen edit'},row('added','video')]});
const before=JSON.stringify([frozenLists,frozenOverrides]);
result=merge(frozenLists,frozenOverrides);
assert.equal(JSON.stringify([frozenLists,frozenOverrides]),before);
assert.deepEqual(ids(result),['youtube','added','russia_inside','google_ai','global']);
assert.notEqual(result[0],frozenOverrides.video[0]);
assert.notEqual(result[2],frozenLists[1]);
result[0].name='Output may be edited';
assert.equal(frozenOverrides.video[0].name,'Frozen edit');

assert.match(source,/get:function\(\)\{return atlasMergeSectionLists\(s\.remote_lists \|\| \[\],sectionListOverrides\);\}/);
assert.match(source,/parsedLists=atlasMergeSectionLists\(parsedLists,sectionListOverrides\);/);
assert(!source.includes('parsedLists=parsedLists.filter(function(item){return !Object.prototype.hasOwnProperty.call(sectionListOverrides,item.section);})'));
console.log('PASS: section list edits retain routing priority; multiple edits do not reshuffle sources; deletion/addition anchors and new sections are correct; inputs stay unchanged.');
