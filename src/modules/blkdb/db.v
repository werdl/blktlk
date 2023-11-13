module blkdb

import json
import crypto.sha256
import time
import crypto.rand

fn u8str(data []u8) string {
	return json.encode(data)
}

fn stru8(data string) []u8 {
	return json.decode([]u8, data) or { []u8{} }
}

pub struct Block {
	ident string
	timestamp string
	hash string
	prev_hash string
	accessable bool
	pub: data map[string]string
}


pub struct Table {
	structure []string 
	name string 
	mut:data []Block
}

fn (b Block) hash() Block {
	tohash:=json.encode(b.data)+b.timestamp+b.ident+b.prev_hash+b.accessable.str()
	return Block{
		data: b.data
		timestamp: b.timestamp
		ident: b.ident
		hash: sha256.hexhash(tohash)
		prev_hash: b.prev_hash
		accessable: b.accessable
	}
}

fn (t Table) new(data map[string]string, accessable bool) !Block {
	blocka:=Block{
		data: data
		timestamp: time.now().format_rfc3339()
		ident: rand.bytes(64)!.hex()
		accessable: accessable
		hash: ""
		prev_hash: t.data[t.data.len-1].hash
	}
	blockb:=blocka.hash()
	return blockb
}

fn (b Block) verify(oldblock Block) bool {
	if b.prev_hash!=oldblock.hash {
		return false
	} else if b.hash().hash!=b.hash {
		return false
	} else {
		return true
	}
}

fn (mut t Table) genesis() !{
	mut datamap:=map[string]string{}
	for column in t.structure {
		datamap[column]="genesis"
	}
	t.data << Block{
		data: datamap
		timestamp: time.now().format_rfc3339()
		ident: rand.bytes(64)!.hex()
		accessable: false
		hash: "genesis"
		prev_hash: "genesis"
	}
	t.data << t.new(datamap, false)!
	x:=t.new(datamap, false)!
	t.data << x	
}

pub fn Table.init(name string, structure []string) Table {
	mut x:=Table{
		data: []Block{}
		structure: structure
		name: name
	}
	x.genesis() or { panic(err) }
	return x
}

pub fn (mut t Table) insert(data map[string]string) bool {
	for i in 0..data.len {
		if data.keys()[i] !in t.structure {
			return false
		}
	}
	t.data << t.new(data, true) or { return false }
	return true
}


pub fn (t Table) where(column string, targets []string, op string) []Block {
	mut toret:=[]Block{}
	mut oldentry:=Block{}
	for entry in t.data {
		if entry.accessable {
			if entry.verify(oldentry) {
				if column in entry.data {
					for target in targets {
						match op {
							"in" {
								if entry.data[column].contains(target) {
									toret << entry
								}
							} else { // ideally match
								if target==entry.data[column] {
									toret << entry
								}
							}
						}
						
					}
				}
			}
		}
		oldentry=entry
	}
	return toret

}
