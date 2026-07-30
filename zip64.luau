--!strict
--!native
--!optimize 2

const LEN_BASE = buffer.fromstring("\3\0\4\0\5\0\6\0\7\0\8\0\9\0\10\0\11\0\13\0\15\0\17\0\19\0\23\0\27\0\31\0\35\0\43\0\51\0\59\0\67\0\83\0\99\0\115\0\131\0\163\0\195\0\227\0\2\1")
const LEN_EXTRA = buffer.fromstring("\0\0\0\0\0\0\0\0\1\1\1\1\2\2\2\2\3\3\3\3\4\4\4\4\5\5\5\5\0")

const DIST_BASE = buffer.fromstring("\1\0\2\0\3\0\4\0\5\0\7\0\9\0\13\0\17\0\25\0\33\0\49\0\65\0\97\0\129\0\193\0\1\1\129\1\1\2\1\3\1\4\1\6\1\8\1\12\1\16\1\24\1\32\1\48\1\64\1\96")
const DIST_EXTRA = buffer.fromstring("\0\0\0\0\1\1\2\2\3\3\4\4\5\5\6\6\7\7\8\8\9\9\10\10\11\11\12\12\13\13")
const CL_ORDER = buffer.fromstring("\16\17\18\0\8\7\9\6\10\5\11\4\12\3\13\2\14\1\15")

const LOCAL_FILE_HEADER = 0x04034B50
const CENTRAL_DIRECTORY_ENTRY = 0x02014B50
const END_OF_CENTRAL_DIRECTORY = 0x06054B50
const ZIP64_END_OF_CENTRAL_DIRECTORY = 0x06064B50
const ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR = 0x07064B50
const ZIP64_EXTRA_FIELD = 0x0001

const METHOD_STORE = 0
const METHOD_DEFLATE = 8
const UTF8_FLAG = 0x0800
const VERSION_20 = 20
const VERSION_45 = 45

const INTEGER_U16_SENTINEL = 0xFFFFi
const INTEGER_U32_SENTINEL = 0xFFFFFFFFi

const MIN_MATCH = 3
const MAX_MATCH = 258
const WINDOW_SIZE = 32768
const WINDOW_MASK = WINDOW_SIZE - 1
const CHAIN_SIZE = 65536
const CHAIN_MASK = CHAIN_SIZE - 1
const HASH_SIZE = 65536
const HASH_MASK = HASH_SIZE - 1
const MATCH_MARKER = 0x40000000
const DEFAULT_SEARCH_DEPTH = 64
const MAX_SEARCH_DEPTH = 512

const LENGTH_CODE = buffer.create(256)
for Index = 0, 28 do
	const Base = buffer.readu16(LEN_BASE, Index * 2)
	const Extra = buffer.readu8(LEN_EXTRA, Index)
	const Last = if Index == 28 then MAX_MATCH else Base + bit32.lshift(1, Extra) - 1
	for Length = Base, Last do
		buffer.writeu8(LENGTH_CODE, Length - MIN_MATCH, Index)
	end
end

const DISTANCE_CODE = buffer.create(WINDOW_SIZE)
for Index = 0, 29 do
	const Base = buffer.readu16(DIST_BASE, Index * 2)
	const Extra = buffer.readu8(DIST_EXTRA, Index)
	const Last = Base + bit32.lshift(1, Extra) - 1
	for Distance = Base, Last do
		buffer.writeu8(DISTANCE_CODE, Distance - 1, Index)
	end
end

const CRC_TABLES = buffer.create(8 * 256 * 4)
for Index = 0, 255 do
	local Value = Index
	for _ = 1, 8 do
		if bit32.band(Value, 1) ~= 0 then
			Value = bit32.bxor(Value // 2, 0xEDB88320)
		else
			Value //= 2
		end
	end
	buffer.writeu32(CRC_TABLES, Index * 4, Value)
end

for Slice = 1, 7 do
	for Index = 0, 255 do
		const Prev = buffer.readu32(CRC_TABLES, ((Slice - 1) * 256 + Index) * 4)
		buffer.writeu32(CRC_TABLES, (Slice * 256 + Index) * 4, bit32.bxor(Prev // 256, buffer.readu32(CRC_TABLES, bit32.band(Prev, 0xFF) * 4)))
	end
end

@[native, checked] const function ReverseBits(Value: number, Count: number): number
	local Result = 0
	for _ = 1, Count do
		Result = bit32.bor(Result * 2, bit32.band(Value, 1))
		Value //= 2
	end
	return Result
end

@[native, checked] const function CRC32(Data: buffer): number
	const Size = buffer.len(Data)
	local CRC = 0xFFFFFFFF
	local Position = 0

	while Position + 8 <= Size do
		const Value = bit32.bxor(CRC, buffer.readu32(Data, Position))
		CRC = bit32.bxor(
			buffer.readu32(CRC_TABLES, 0x1C00 + bit32.band(Value, 0xFF) * 4),
			buffer.readu32(CRC_TABLES, 0x1800 + bit32.band(Value // 256, 0xFF) * 4),
			buffer.readu32(CRC_TABLES, 0x1400 + bit32.band(Value // 65536, 0xFF) * 4),
			buffer.readu32(CRC_TABLES, 0x1000 + (Value // 16777216) * 4),
			buffer.readu32(CRC_TABLES, 0x0C00 + buffer.readu8(Data, Position + 4) * 4),
			buffer.readu32(CRC_TABLES, 0x0800 + buffer.readu8(Data, Position + 5) * 4),
			buffer.readu32(CRC_TABLES, 0x0400 + buffer.readu8(Data, Position + 6) * 4),
			buffer.readu32(CRC_TABLES, buffer.readu8(Data, Position + 7) * 4)
		)
		Position += 8
	end

	while Position < Size do
		const Index = bit32.band(bit32.bxor(CRC, buffer.readu8(Data, Position)), 0xFF)
		CRC = bit32.bxor(CRC // 256, buffer.readu32(CRC_TABLES, Index * 4))
		Position += 1
	end

	return bit32.bxor(CRC, 0xFFFFFFFF)
end

@[native, checked] const function Hash3(Data: buffer, Position: number): number
	const Value = buffer.readu16(Data, Position) + buffer.readu8(Data, Position + 2) * 0x10000
	return bit32.band(bit32.bxor(Value, Value // 512, Value * 32), HASH_MASK)
end

@[native, checked] const function Hash4(Data: buffer, Position: number): number
	const Value = bit32.band(buffer.readu32(Data, Position), 0xFFFFFF)
	return bit32.band(bit32.bxor(Value, Value // 512, Value * 32), HASH_MASK)
end

@[native, checked] const function Less(Frequencies: buffer, A: number, B: number): boolean
	const AFrequency = buffer.readu32(Frequencies, A * 4)
	const BFrequency = buffer.readu32(Frequencies, B * 4)
	return AFrequency < BFrequency or (AFrequency == BFrequency and A < B)
end

@[native, checked] const function HeapPush(Heap: buffer, HeapSize: number, Frequencies: buffer, Node: number): number
	local Index = HeapSize
	while Index > 0 do
		const Parent = (Index - 1) // 2
		const ParentNode = buffer.readu16(Heap, Parent * 2)
		if not Less(Frequencies, Node, ParentNode) then
			break
		end
		buffer.writeu16(Heap, Index * 2, ParentNode)
		Index = Parent
	end
	buffer.writeu16(Heap, Index * 2, Node)
	return HeapSize + 1
end

@[native, checked] const function HeapPop(Heap: buffer, HeapSize: number, Frequencies: buffer): (number, number)
	const Root = buffer.readu16(Heap, 0)
	HeapSize -= 1

	if HeapSize ~= 0 then
		const Last = buffer.readu16(Heap, HeapSize * 2)
		local Index = 0

		while true do
			local Child = Index * 2 + 1
			if Child >= HeapSize then
				break
			end

			if Child + 1 < HeapSize then
				const Left = buffer.readu16(Heap, Child * 2)
				const Right = buffer.readu16(Heap, (Child + 1) * 2)
				if Less(Frequencies, Right, Left) then
					Child += 1
				end
			end

			const ChildNode = buffer.readu16(Heap, Child * 2)
			if not Less(Frequencies, ChildNode, Last) then
				break
			end

			buffer.writeu16(Heap, Index * 2, ChildNode)
			Index = Child
		end

		buffer.writeu16(Heap, Index * 2, Last)
	end

	return Root, HeapSize
end

@[native, checked] const function BuildCodeLengths(Frequencies: buffer, SymbolCount: number, MaxBits: number): buffer
	const Lengths = buffer.create(SymbolCount)
	const NodeCapacity = SymbolCount * 2 + 1
	const WorkFrequencies = buffer.create(NodeCapacity * 4)
	const Parents = buffer.create(NodeCapacity * 2)
	const Heap = buffer.create(SymbolCount * 2)
	const Active = buffer.create(SymbolCount * 2)

	buffer.copy(WorkFrequencies, 0, Frequencies, 0, SymbolCount * 4)

	local ActiveCount = 0
	local HeapSize = 0
	for Symbol = 0, SymbolCount - 1 do
		if buffer.readu32(WorkFrequencies, Symbol * 4) ~= 0 then
			buffer.writeu16(Active, ActiveCount * 2, Symbol)
			ActiveCount += 1
			HeapSize = HeapPush(Heap, HeapSize, WorkFrequencies, Symbol)
		end
	end

	if ActiveCount == 0 then
		return Lengths
	end

	if ActiveCount == 1 then
		const Only = buffer.readu16(Active, 0)
		const Dummy = if Only == 0 then 1 else 0

		buffer.writeu32(WorkFrequencies, Dummy * 4, 1)
		buffer.writeu16(Active, ActiveCount * 2, Dummy)
		ActiveCount += 1
		HeapSize = HeapPush(Heap, HeapSize, WorkFrequencies, Dummy)
	end

	local NextNode = SymbolCount
	while HeapSize > 1 do
		local A = 0
		local B = 0
		A, HeapSize = HeapPop(Heap, HeapSize, WorkFrequencies)
		B, HeapSize = HeapPop(Heap, HeapSize, WorkFrequencies)

		buffer.writeu32(WorkFrequencies, NextNode * 4, buffer.readu32(WorkFrequencies, A * 4) + buffer.readu32(WorkFrequencies, B * 4))
		buffer.writeu16(Parents, A * 2, NextNode)
		buffer.writeu16(Parents, B * 2, NextNode)
		HeapSize = HeapPush(Heap, HeapSize, WorkFrequencies, NextNode)
		NextNode += 1
	end

	const Root = buffer.readu16(Heap, 0)
	const BitCounts = buffer.create((MaxBits + 1) * 4)
	local Overflow = 0

	for Index = 0, ActiveCount - 1 do
		local Node = buffer.readu16(Active, Index * 2)
		local Length = 0
		while Node ~= Root do
			Node = buffer.readu16(Parents, Node * 2)
			Length += 1
		end

		if Length > MaxBits then
			Length = MaxBits
			Overflow += 1
		end

		const Offset = Length * 4
		buffer.writeu32(BitCounts, Offset, buffer.readu32(BitCounts, Offset) + 1)
	end

	while Overflow > 0 do
		local Bits = MaxBits - 1
		while buffer.readu32(BitCounts, Bits * 4) == 0 do
			Bits -= 1
		end

		buffer.writeu32(BitCounts, Bits * 4, buffer.readu32(BitCounts, Bits * 4) - 1)
		buffer.writeu32(BitCounts, (Bits + 1) * 4, buffer.readu32(BitCounts, (Bits + 1) * 4) + 2)
		buffer.writeu32(BitCounts, MaxBits * 4, buffer.readu32(BitCounts, MaxBits * 4) - 1)
		Overflow -= 2
	end

	HeapSize = 0
	for ActiveIndex = 0, ActiveCount - 1 do
		HeapSize = HeapPush(Heap, HeapSize, WorkFrequencies, buffer.readu16(Active, ActiveIndex * 2))
	end

	for Bits = MaxBits, 1, -1 do
		for _ = 1, buffer.readu32(BitCounts, Bits * 4) do
			local Symbol = 0
			Symbol, HeapSize = HeapPop(Heap, HeapSize, WorkFrequencies)
			buffer.writeu8(Lengths, Symbol, Bits)
		end
	end

	return Lengths
end

@[native, checked] const function BuildCodes(Lengths: buffer, SymbolCount: number): buffer
	const BitCounts = buffer.create(64)
	local MaxBits = 0

	for Symbol = 0, SymbolCount - 1 do
		const Length = buffer.readu8(Lengths, Symbol)
		if Length ~= 0 then
			const Offset = Length * 4
			buffer.writeu32(BitCounts, Offset, buffer.readu32(BitCounts, Offset) + 1)
			if Length > MaxBits then
				MaxBits = Length
			end
		end
	end

	const NextCode = buffer.create(64)
	local Code = 0
	for Bits = 1, MaxBits do
		Code = (Code + buffer.readu32(BitCounts, (Bits - 1) * 4)) * 2
		buffer.writeu32(NextCode, Bits * 4, Code)
	end

	const Codes = buffer.create(SymbolCount * 2)
	for Symbol = 0, SymbolCount - 1 do
		const Length = buffer.readu8(Lengths, Symbol)
		if Length ~= 0 then
			const Offset = Length * 4
			const Value = buffer.readu32(NextCode, Offset)
			buffer.writeu32(NextCode, Offset, Value + 1)
			buffer.writeu16(Codes, Symbol * 2, ReverseBits(Value, Length))
		end
	end

	return Codes
end

@[native, checked] const function BuildHuffman(Lengths: buffer, SymbolCount: number): (buffer, number)
	const BitCounts = buffer.create(64)
	local MaxBits = 0

	for Symbol = 0, SymbolCount - 1 do
		const Length = buffer.readu8(Lengths, Symbol)
		if Length > 15 then
			error("Invalid Huffman code length")
		end
		if Length ~= 0 then
			const Offset = Length * 4
			buffer.writeu32(BitCounts, Offset, buffer.readu32(BitCounts, Offset) + 1)
			if Length > MaxBits then
				MaxBits = Length
			end
		end
	end

	if MaxBits == 0 then
		return buffer.create(4), 0
	end

	const NextCode = buffer.create(64)
	local Code = 0
	for Bits = 1, MaxBits do
		Code = (Code + buffer.readu32(BitCounts, (Bits - 1) * 4)) * 2
		buffer.writeu32(NextCode, Bits * 4, Code)
	end

	if Code + buffer.readu32(BitCounts, MaxBits * 4) > bit32.lshift(1, MaxBits) then
		error("Oversubscribed Huffman tree")
	end

	const Size = bit32.lshift(1, MaxBits)
	const Lut = buffer.create(Size * 4)

	for Symbol = 0, SymbolCount - 1 do
		const Length = buffer.readu8(Lengths, Symbol)
		if Length ~= 0 then
			const Offset = Length * 4
			const Value = buffer.readu32(NextCode, Offset)
			buffer.writeu32(NextCode, Offset, Value + 1)

			const Key = ReverseBits(Value, Length)
			const Entry = bit32.bor(Symbol, Length * 65536)
			const Step = bit32.lshift(1, Length)
			for Index = Key, Size - 1, Step do
				buffer.writeu32(Lut, Index * 4, Entry)
			end
		end
	end

	return Lut, MaxBits
end

const FIXED_LIT_LUT = buffer.fromstring("\0\1\7\0\80\0\8\0\16\0\8\0\24\1\8\0\16\1\7\0\112\0\8\0\48\0\8\0\192\0\9\0\8\1\7\0\96\0\8\0\32\0\8\0\160\0\9\0\0\0\8\0\128\0\8\0\64\0\8\0\224\0\9\0\4\1\7\0\88\0\8\0\24\0\8\0\144\0\9\0\20\1\7\0\120\0\8\0\56\0\8\0\208\0\9\0\12\1\7\0\104\0\8\0\40\0\8\0\176\0\9\0\8\0\8\0\136\0\8\0\72\0\8\0\240\0\9\0\2\1\7\0\84\0\8\0\20\0\8\0\28\1\8\0\18\1\7\0\116\0\8\0\52\0\8\0\200\0\9\0\10\1\7\0\100\0\8\0\36\0\8\0\168\0\9\0\4\0\8\0\132\0\8\0\68\0\8\0\232\0\9\0\6\1\7\0\92\0\8\0\28\0\8\0\152\0\9\0\22\1\7\0\124\0\8\0\60\0\8\0\216\0\9\0\14\1\7\0\108\0\8\0\44\0\8\0\184\0\9\0\12\0\8\0\140\0\8\0\76\0\8\0\248\0\9\0\1\1\7\0\82\0\8\0\18\0\8\0\26\1\8\0\17\1\7\0\114\0\8\0\50\0\8\0\196\0\9\0\9\1\7\0\98\0\8\0\34\0\8\0\164\0\9\0\2\0\8\0\130\0\8\0\66\0\8\0\228\0\9\0\5\1\7\0\90\0\8\0\26\0\8\0\148\0\9\0\21\1\7\0\122\0\8\0\58\0\8\0\212\0\9\0\13\1\7\0\106\0\8\0\42\0\8\0\180\0\9\0\10\0\8\0\138\0\8\0\74\0\8\0\244\0\9\0\3\1\7\0\86\0\8\0\22\0\8\0\30\1\8\0\19\1\7\0\118\0\8\0\54\0\8\0\204\0\9\0\11\1\7\0\102\0\8\0\38\0\8\0\172\0\9\0\6\0\8\0\134\0\8\0\70\0\8\0\236\0\9\0\7\1\7\0\94\0\8\0\30\0\8\0\156\0\9\0\23\1\7\0\126\0\8\0\62\0\8\0\220\0\9\0\15\1\7\0\110\0\8\0\46\0\8\0\188\0\9\0\14\0\8\0\142\0\8\0\78\0\8\0\252\0\9\0\0\1\7\0\81\0\8\0\17\0\8\0\25\1\8\0\16\1\7\0\113\0\8\0\49\0\8\0\194\0\9\0\8\1\7\0\97\0\8\0\33\0\8\0\162\0\9\0\1\0\8\0\129\0\8\0\65\0\8\0\226\0\9\0\4\1\7\0\89\0\8\0\25\0\8\0\146\0\9\0\20\1\7\0\121\0\8\0\57\0\8\0\210\0\9\0\12\1\7\0\105\0\8\0\41\0\8\0\178\0\9\0\9\0\8\0\137\0\8\0\73\0\8\0\242\0\9\0\2\1\7\0\85\0\8\0\21\0\8\0\29\1\8\0\18\1\7\0\117\0\8\0\53\0\8\0\202\0\9\0\10\1\7\0\101\0\8\0\37\0\8\0\170\0\9\0\5\0\8\0\133\0\8\0\69\0\8\0\234\0\9\0\6\1\7\0\93\0\8\0\29\0\8\0\154\0\9\0\22\1\7\0\125\0\8\0\61\0\8\0\218\0\9\0\14\1\7\0\109\0\8\0\45\0\8\0\186\0\9\0\13\0\8\0\141\0\8\0\77\0\8\0\250\0\9\0\1\1\7\0\83\0\8\0\19\0\8\0\27\1\8\0\17\1\7\0\115\0\8\0\51\0\8\0\198\0\9\0\9\1\7\0\99\0\8\0\35\0\8\0\166\0\9\0\3\0\8\0\131\0\8\0\67\0\8\0\230\0\9\0\5\1\7\0\91\0\8\0\27\0\8\0\150\0\9\0\21\1\7\0\123\0\8\0\59\0\8\0\214\0\9\0\13\1\7\0\107\0\8\0\43\0\8\0\182\0\9\0\11\0\8\0\139\0\8\0\75\0\8\0\246\0\9\0\3\1\7\0\87\0\8\0\23\0\8\0\31\1\8\0\19\1\7\0\119\0\8\0\55\0\8\0\206\0\9\0\11\1\7\0\103\0\8\0\39\0\8\0\174\0\9\0\7\0\8\0\135\0\8\0\71\0\8\0\238\0\9\0\7\1\7\0\95\0\8\0\31\0\8\0\158\0\9\0\23\1\7\0\127\0\8\0\63\0\8\0\222\0\9\0\15\1\7\0\111\0\8\0\47\0\8\0\190\0\9\0\15\0\8\0\143\0\8\0\79\0\8\0\254\0\9\0\0\1\7\0\80\0\8\0\16\0\8\0\24\1\8\0\16\1\7\0\112\0\8\0\48\0\8\0\193\0\9\0\8\1\7\0\96\0\8\0\32\0\8\0\161\0\9\0\0\0\8\0\128\0\8\0\64\0\8\0\225\0\9\0\4\1\7\0\88\0\8\0\24\0\8\0\145\0\9\0\20\1\7\0\120\0\8\0\56\0\8\0\209\0\9\0\12\1\7\0\104\0\8\0\40\0\8\0\177\0\9\0\8\0\8\0\136\0\8\0\72\0\8\0\241\0\9\0\2\1\7\0\84\0\8\0\20\0\8\0\28\1\8\0\18\1\7\0\116\0\8\0\52\0\8\0\201\0\9\0\10\1\7\0\100\0\8\0\36\0\8\0\169\0\9\0\4\0\8\0\132\0\8\0\68\0\8\0\233\0\9\0\6\1\7\0\92\0\8\0\28\0\8\0\153\0\9\0\22\1\7\0\124\0\8\0\60\0\8\0\217\0\9\0\14\1\7\0\108\0\8\0\44\0\8\0\185\0\9\0\12\0\8\0\140\0\8\0\76\0\8\0\249\0\9\0\1\1\7\0\82\0\8\0\18\0\8\0\26\1\8\0\17\1\7\0\114\0\8\0\50\0\8\0\197\0\9\0\9\1\7\0\98\0\8\0\34\0\8\0\165\0\9\0\2\0\8\0\130\0\8\0\66\0\8\0\229\0\9\0\5\1\7\0\90\0\8\0\26\0\8\0\149\0\9\0\21\1\7\0\122\0\8\0\58\0\8\0\213\0\9\0\13\1\7\0\106\0\8\0\42\0\8\0\181\0\9\0\10\0\8\0\138\0\8\0\74\0\8\0\245\0\9\0\3\1\7\0\86\0\8\0\22\0\8\0\30\1\8\0\19\1\7\0\118\0\8\0\54\0\8\0\205\0\9\0\11\1\7\0\102\0\8\0\38\0\8\0\173\0\9\0\6\0\8\0\134\0\8\0\70\0\8\0\237\0\9\0\7\1\7\0\94\0\8\0\30\0\8\0\157\0\9\0\23\1\7\0\126\0\8\0\62\0\8\0\221\0\9\0\15\1\7\0\110\0\8\0\46\0\8\0\189\0\9\0\14\0\8\0\142\0\8\0\78\0\8\0\253\0\9\0\0\1\7\0\81\0\8\0\17\0\8\0\25\1\8\0\16\1\7\0\113\0\8\0\49\0\8\0\195\0\9\0\8\1\7\0\97\0\8\0\33\0\8\0\163\0\9\0\1\0\8\0\129\0\8\0\65\0\8\0\227\0\9\0\4\1\7\0\89\0\8\0\25\0\8\0\147\0\9\0\20\1\7\0\121\0\8\0\57\0\8\0\211\0\9\0\12\1\7\0\105\0\8\0\41\0\8\0\179\0\9\0\9\0\8\0\137\0\8\0\73\0\8\0\243\0\9\0\2\1\7\0\85\0\8\0\21\0\8\0\29\1\8\0\18\1\7\0\117\0\8\0\53\0\8\0\203\0\9\0\10\1\7\0\101\0\8\0\37\0\8\0\171\0\9\0\5\0\8\0\133\0\8\0\69\0\8\0\235\0\9\0\6\1\7\0\93\0\8\0\29\0\8\0\155\0\9\0\22\1\7\0\125\0\8\0\61\0\8\0\219\0\9\0\14\1\7\0\109\0\8\0\45\0\8\0\187\0\9\0\13\0\8\0\141\0\8\0\77\0\8\0\251\0\9\0\1\1\7\0\83\0\8\0\19\0\8\0\27\1\8\0\17\1\7\0\115\0\8\0\51\0\8\0\199\0\9\0\9\1\7\0\99\0\8\0\35\0\8\0\167\0\9\0\3\0\8\0\131\0\8\0\67\0\8\0\231\0\9\0\5\1\7\0\91\0\8\0\27\0\8\0\151\0\9\0\21\1\7\0\123\0\8\0\59\0\8\0\215\0\9\0\13\1\7\0\107\0\8\0\43\0\8\0\183\0\9\0\11\0\8\0\139\0\8\0\75\0\8\0\247\0\9\0\3\1\7\0\87\0\8\0\23\0\8\0\31\1\8\0\19\1\7\0\119\0\8\0\55\0\8\0\207\0\9\0\11\1\7\0\103\0\8\0\39\0\8\0\175\0\9\0\7\0\8\0\135\0\8\0\71\0\8\0\239\0\9\0\7\1\7\0\95\0\8\0\31\0\8\0\159\0\9\0\23\1\7\0\127\0\8\0\63\0\8\0\223\0\9\0\15\1\7\0\111\0\8\0\47\0\8\0\191\0\9\0\15\0\8\0\143\0\8\0\79\0\8\0\255\0\9\0")
const FIXED_LIT_MAX = 9
const FIXED_DIST_LUT = buffer.fromstring("\0\0\5\0\16\0\5\0\8\0\5\0\24\0\5\0\4\0\5\0\20\0\5\0\12\0\5\0\28\0\5\0\2\0\5\0\18\0\5\0\10\0\5\0\26\0\5\0\6\0\5\0\22\0\5\0\14\0\5\0\0\0\0\0\1\0\5\0\17\0\5\0\9\0\5\0\25\0\5\0\5\0\5\0\21\0\5\0\13\0\5\0\29\0\5\0\3\0\5\0\19\0\5\0\11\0\5\0\27\0\5\0\7\0\5\0\23\0\5\0\15\0\5\0\0\0\0\0")
const FIXED_DIST_MAX = 5


@[native, checked] const function Tokenize(Data: buffer, SearchDepth: number): (buffer, number, buffer, buffer)
	const Size = buffer.len(Data)
	const Tokens = buffer.create(math.max(Size, 1) * 4)
	const LitFrequencies = buffer.create(286 * 4)
	const DistFrequencies = buffer.create(30 * 4)
	const Head = buffer.create(HASH_SIZE * 4)
	const Previous = buffer.create(CHAIN_SIZE * 4)
	const LastHashPosition = Size - MIN_MATCH

	local Position = 0
	local TokenCount = 0

	while Position < Size do
		local BestLength = 0
		local BestDistance = 0

		if Position <= LastHashPosition then
			const Hash = Hash3(Data, Position)
			local CandidateEntry = buffer.readu32(Head, Hash * 4)

			buffer.writeu32(Previous, bit32.band(Position, CHAIN_MASK) * 4, CandidateEntry)
			buffer.writeu32(Head, Hash * 4, Position + 1)

			const Limit = math.min(MAX_MATCH, Size - Position)
			const Prefix = buffer.readu16(Data, Position)
			const Third = buffer.readu8(Data, Position + 2)
			local Searches = 0

			while CandidateEntry ~= 0 and Searches < SearchDepth do
				const Candidate = CandidateEntry - 1
				const Distance = Position - Candidate

				if Distance > WINDOW_SIZE or Distance <= 0 then
					break
				end

				if buffer.readu16(Data, Candidate) == Prefix
					and buffer.readu8(Data, Candidate + 2) == Third
				then
					local Length = MIN_MATCH
					while Length + 4 <= Limit and buffer.readu32(Data, Candidate + Length) == buffer.readu32(Data, Position + Length) do
						Length += 4
					end
					while Length < Limit and buffer.readu8(Data, Candidate + Length) == buffer.readu8(Data, Position + Length) do
						Length += 1
					end

					if Length > BestLength then
						BestLength = Length
						BestDistance = Distance
						if Length == Limit then
							break
						end
					end
				end

				CandidateEntry = buffer.readu32(Previous, bit32.band(Candidate, CHAIN_MASK) * 4)
				Searches += 1
			end
		end

		if BestLength >= MIN_MATCH then
			const Token = MATCH_MARKER + (BestLength - MIN_MATCH) * 32768 + BestDistance - 1
			buffer.writeu32(Tokens, TokenCount * 4, Token)
			TokenCount += 1

			const LenIndex = buffer.readu8(LENGTH_CODE, BestLength - MIN_MATCH)
			const DistIndex = buffer.readu8(DISTANCE_CODE, BestDistance - 1)
			const LitOffset = (257 + LenIndex) * 4
			const DistOffset = DistIndex * 4
			buffer.writeu32(LitFrequencies, LitOffset, buffer.readu32(LitFrequencies, LitOffset) + 1)
			buffer.writeu32(DistFrequencies, DistOffset, buffer.readu32(DistFrequencies, DistOffset) + 1)

			const InsertEnd = math.min(Position + BestLength - 1, LastHashPosition)
			const FastInsertEnd = math.min(InsertEnd, LastHashPosition - 1)
			for InsertPosition = Position + 1, FastInsertEnd do
				const Hash = Hash4(Data, InsertPosition)
				const CandidateEntry = buffer.readu32(Head, Hash * 4)
				buffer.writeu32(Previous, bit32.band(InsertPosition, CHAIN_MASK) * 4, CandidateEntry)
				buffer.writeu32(Head, Hash * 4, InsertPosition + 1)
			end

			if InsertEnd == LastHashPosition and InsertEnd > FastInsertEnd then
				const Hash = Hash3(Data, InsertEnd)
				const CandidateEntry = buffer.readu32(Head, Hash * 4)
				buffer.writeu32(Previous, bit32.band(InsertEnd, CHAIN_MASK) * 4, CandidateEntry)
				buffer.writeu32(Head, Hash * 4, InsertEnd + 1)
			end

			Position += BestLength
		else
			const Symbol = buffer.readu8(Data, Position)
			buffer.writeu32(Tokens, TokenCount * 4, Symbol)
			TokenCount += 1

			const Offset = Symbol * 4
			buffer.writeu32(LitFrequencies, Offset, buffer.readu32(LitFrequencies, Offset) + 1)
			Position += 1
		end
	end

	buffer.writeu32(LitFrequencies, 256 * 4, buffer.readu32(LitFrequencies, 256 * 4) + 1)

	local HasDistance = false
	for Symbol = 0, 29 do
		if buffer.readu32(DistFrequencies, Symbol * 4) ~= 0 then
			HasDistance = true
			break
		end
	end
	if not HasDistance then
		buffer.writeu32(DistFrequencies, 0, 1)
	end

	return Tokens, TokenCount, LitFrequencies, DistFrequencies
end

@[native, checked] const function EmitRLE(Symbols: buffer, Values: buffer, ExtraBits: buffer, Frequencies: buffer, Position: number, Symbol: number, Value: number, BitCount: number): number
	buffer.writeu8(Symbols, Position, Symbol)
	buffer.writeu8(Values, Position, Value)
	buffer.writeu8(ExtraBits, Position, BitCount)
	const Offset = Symbol * 4
	buffer.writeu32(Frequencies, Offset, buffer.readu32(Frequencies, Offset) + 1)
	return Position + 1
end

@[native, checked] const function EncodeCodeLengths(AllLengths: buffer, Count: number): (buffer, buffer, buffer, number, buffer)
	const Symbols = buffer.create(Count)
	const Values = buffer.create(Count)
	const ExtraBits = buffer.create(Count)
	const Frequencies = buffer.create(19 * 4)

	local InputPos = 0
	local OutputPos = 0

	while InputPos < Count do
		const Value = buffer.readu8(AllLengths, InputPos)
		local RunEnd = InputPos + 1
		while RunEnd < Count and buffer.readu8(AllLengths, RunEnd) == Value do
			RunEnd += 1
		end

		local Run = RunEnd - InputPos
		if Value == 0 then
			while Run >= 11 do
				const Repeat = math.min(Run, 138)
				OutputPos = EmitRLE(Symbols, Values, ExtraBits, Frequencies, OutputPos, 18, Repeat - 11, 7)
				Run -= Repeat
			end
			if Run >= 3 then
				const Repeat = math.min(Run, 10)
				OutputPos = EmitRLE(Symbols, Values, ExtraBits, Frequencies, OutputPos, 17, Repeat - 3, 3)
				Run -= Repeat
			end
			while Run > 0 do
				OutputPos = EmitRLE(Symbols, Values, ExtraBits, Frequencies, OutputPos, 0, 0, 0)
				Run -= 1
			end
		else
			OutputPos = EmitRLE(Symbols, Values, ExtraBits, Frequencies, OutputPos, Value, 0, 0)
			Run -= 1

			while Run >= 3 do
				const Repeat = math.min(Run, 6)
				OutputPos = EmitRLE(Symbols, Values, ExtraBits, Frequencies, OutputPos, 16, Repeat - 3, 2)
				Run -= Repeat
			end
			while Run > 0 do
				OutputPos = EmitRLE(Symbols, Values, ExtraBits, Frequencies, OutputPos, Value, 0, 0)
				Run -= 1
			end
		end

		InputPos = RunEnd
	end

	return Symbols, Values, ExtraBits, OutputPos, Frequencies
end

@[native, checked] const function DeflateStored(Data: buffer): buffer
	const Size = buffer.len(Data)
	const BlockCount = math.max((Size + 65534) // 65535, 1)
	const Output = buffer.create(Size + BlockCount * 5)

	local SourcePos = 0
	local OutputPos = 0
	for Block = 1, BlockCount do
		const Count = math.min(Size - SourcePos, 65535)
		buffer.writeu8(Output, OutputPos, if Block == BlockCount then 1 else 0)
		buffer.writeu16(Output, OutputPos + 1, Count)
		buffer.writeu16(Output, OutputPos + 3, bit32.bxor(Count, 0xFFFF))
		buffer.copy(Output, OutputPos + 5, Data, SourcePos, Count)
		SourcePos += Count
		OutputPos += Count + 5
	end

	return Output
end

@[native, checked] const function Deflate(Data: buffer, SearchDepth: number?): buffer
	const Size = buffer.len(Data)
	const Depth = if SearchDepth then math.clamp(SearchDepth // 1, 1, MAX_SEARCH_DEPTH) else DEFAULT_SEARCH_DEPTH

	const Tokens, TokenCount, LitFrequencies, DistFrequencies = Tokenize(Data, Depth)
	const LitLengths = BuildCodeLengths(LitFrequencies, 286, 15)
	const DistLengths = BuildCodeLengths(DistFrequencies, 30, 15)

	local HLit = 286
	while HLit > 257 and buffer.readu8(LitLengths, HLit - 1) == 0 do
		HLit -= 1
	end

	local HDist = 30
	while HDist > 1 and buffer.readu8(DistLengths, HDist - 1) == 0 do
		HDist -= 1
	end

	const TotalLengths = HLit + HDist
	const AllLengths = buffer.create(TotalLengths)
	buffer.copy(AllLengths, 0, LitLengths, 0, HLit)
	buffer.copy(AllLengths, HLit, DistLengths, 0, HDist)

	const RLESymbols, RLEValues, RLEExtraBits, RLECount, CLFrequencies = EncodeCodeLengths(AllLengths, TotalLengths)
	const CLLengths = BuildCodeLengths(CLFrequencies, 19, 7)

	local HCLen = 19
	while HCLen > 4 and buffer.readu8(CLLengths, buffer.readu8(CL_ORDER, HCLen - 1)) == 0 do
		HCLen -= 1
	end

	local DynamicBits = 17 + HCLen * 3
	for Symbol = 0, 18 do
		DynamicBits += buffer.readu32(CLFrequencies, Symbol * 4) * buffer.readu8(CLLengths, Symbol)
	end
	for Index = 0, RLECount - 1 do
		DynamicBits += buffer.readu8(RLEExtraBits, Index)
	end

	local MatchCount = 0
	for Symbol = 0, 285 do
		const Frequency = buffer.readu32(LitFrequencies, Symbol * 4)
		DynamicBits += Frequency * buffer.readu8(LitLengths, Symbol)
		if Symbol >= 257 then
			DynamicBits += Frequency * buffer.readu8(LEN_EXTRA, Symbol - 257)
			MatchCount += Frequency
		end
	end
	if MatchCount ~= 0 then
		for Symbol = 0, 29 do
			const Frequency = buffer.readu32(DistFrequencies, Symbol * 4)
			DynamicBits += Frequency * (buffer.readu8(DistLengths, Symbol) + buffer.readu8(DIST_EXTRA, Symbol))
		end
	end

	const DynamicSize = (DynamicBits + 7) // 8
	const StoredSize = Size + math.max((Size + 65534) // 65535, 1) * 5
	if StoredSize <= DynamicSize then
		return DeflateStored(Data)
	end

	const LitCodes = BuildCodes(LitLengths, 286)
	const DistCodes = BuildCodes(DistLengths, 30)
	const CLCodes = BuildCodes(CLLengths, 19)
	const Output = buffer.create(DynamicSize)
	local BitPos = 0

	buffer.writebits(Output, BitPos, 3, 5)
	BitPos += 3
	buffer.writebits(Output, BitPos, 5, HLit - 257)
	BitPos += 5
	buffer.writebits(Output, BitPos, 5, HDist - 1)
	BitPos += 5
	buffer.writebits(Output, BitPos, 4, HCLen - 4)
	BitPos += 4

	for Index = 0, HCLen - 1 do
		buffer.writebits(Output, BitPos, 3, buffer.readu8(CLLengths, buffer.readu8(CL_ORDER, Index)))
		BitPos += 3
	end

	for Index = 0, RLECount - 1 do
		const Symbol = buffer.readu8(RLESymbols, Index)
		const Length = buffer.readu8(CLLengths, Symbol)
		buffer.writebits(Output, BitPos, Length, buffer.readu16(CLCodes, Symbol * 2))
		BitPos += Length

		const Extra = buffer.readu8(RLEExtraBits, Index)
		if Extra ~= 0 then
			buffer.writebits(Output, BitPos, Extra, buffer.readu8(RLEValues, Index))
			BitPos += Extra
		end
	end

	for Index = 0, TokenCount - 1 do
		const Token = buffer.readu32(Tokens, Index * 4)
		if Token < MATCH_MARKER then
			const Length = buffer.readu8(LitLengths, Token)
			buffer.writebits(Output, BitPos, Length, buffer.readu16(LitCodes, Token * 2))
			BitPos += Length
		else
			const MatchLength = bit32.band(Token // 32768, 0xFF) + MIN_MATCH
			const Distance = bit32.band(Token, WINDOW_MASK) + 1

			const LenIndex = buffer.readu8(LENGTH_CODE, MatchLength - MIN_MATCH)
			const LenSymbol = 257 + LenIndex
			const LenBits = buffer.readu8(LitLengths, LenSymbol)
			buffer.writebits(Output, BitPos, LenBits, buffer.readu16(LitCodes, LenSymbol * 2))
			BitPos += LenBits

			const LenExtra = buffer.readu8(LEN_EXTRA, LenIndex)
			if LenExtra ~= 0 then
				buffer.writebits(Output, BitPos, LenExtra, MatchLength - buffer.readu16(LEN_BASE, LenIndex * 2))
				BitPos += LenExtra
			end

			const DistIndex = buffer.readu8(DISTANCE_CODE, Distance - 1)
			const DistBits = buffer.readu8(DistLengths, DistIndex)
			buffer.writebits(Output, BitPos, DistBits, buffer.readu16(DistCodes, DistIndex * 2))
			BitPos += DistBits

			const DistExtra = buffer.readu8(DIST_EXTRA, DistIndex)
			if DistExtra ~= 0 then
				buffer.writebits(Output, BitPos, DistExtra, Distance - buffer.readu16(DIST_BASE, DistIndex * 2))
				BitPos += DistExtra
			end
		end
	end

	const EndLength = buffer.readu8(LitLengths, 256)
	buffer.writebits(Output, BitPos, EndLength, buffer.readu16(LitCodes, 256 * 2))
	BitPos += EndLength

	if BitPos ~= DynamicBits then
		error("Internal DEFLATE bit count mismatch")
	end
	return Output
end

@[native, checked] const function ReadSymbol(Source: buffer, BitPos: number, BitEnd: number, Lut: buffer, MaxBits: number): (number, number)
	if MaxBits == 0 or BitPos >= BitEnd then
		error("Invalid Huffman stream")
	end

	const Available = BitEnd - BitPos
	const Count = math.min(MaxBits, Available)
	const Key = buffer.readbits(Source, BitPos, Count)
	const Entry = buffer.readu32(Lut, Key * 4)
	const Length = Entry // 65536

	if Length == 0 or Length > Available then
		error("Invalid Huffman symbol")
	end

	return bit32.band(Entry, 0xFFFF), BitPos + Length
end

@[native, checked] const function InflateInto(Source: buffer, SourceBitOffset: number, SourceBitEnd: number, Destination: buffer, DestinationOffset: number): (number, number)
	local BitPos = SourceBitOffset
	local DestinationPos = DestinationOffset
	const DestinationSize = buffer.len(Destination)

	local Final = 0
	while Final == 0 do
		if BitPos + 3 > SourceBitEnd then
			error("DEFLATE block header is truncated")
		end

		Final = buffer.readbits(Source, BitPos, 1)
		const BlockType = buffer.readbits(Source, BitPos + 1, 2)
		BitPos += 3

		if BlockType == 0 then
			BitPos = bit32.band(BitPos + 7, -8)
			const BytePos = BitPos // 8
			if BitPos + 32 > SourceBitEnd then
				error("Stored DEFLATE block is truncated")
			end

			const Length = buffer.readu16(Source, BytePos)
			const NLength = buffer.readu16(Source, BytePos + 2)
			if bit32.band(bit32.bxor(Length, NLength), 0xFFFF) ~= 0xFFFF then
				error("Invalid stored DEFLATE length")
			end
			if BytePos + 4 + Length > SourceBitEnd // 8 or DestinationPos + Length > DestinationSize then
				error("Stored DEFLATE block is out of bounds")
			end

			buffer.copy(Destination, DestinationPos, Source, BytePos + 4, Length)
			DestinationPos += Length
			BitPos = (BytePos + 4 + Length) * 8
		elseif BlockType == 3 then
			error("Invalid DEFLATE block type")
		else
			local LitLut: buffer
			local LitMax: number
			local DistLut: buffer
			local DistMax: number

			if BlockType == 1 then
				LitLut, LitMax = FIXED_LIT_LUT, FIXED_LIT_MAX
				DistLut, DistMax = FIXED_DIST_LUT, FIXED_DIST_MAX
			else
				if BitPos + 14 > SourceBitEnd then
					error("Dynamic DEFLATE header is truncated")
				end

				const HLit = buffer.readbits(Source, BitPos, 5) + 257
				const HDist = buffer.readbits(Source, BitPos + 5, 5) + 1
				const HCLen = buffer.readbits(Source, BitPos + 10, 4) + 4
				BitPos += 14

				if HLit > 286 or HDist > 32 or BitPos + HCLen * 3 > SourceBitEnd then
					error("Invalid dynamic DEFLATE header")
				end

				const CLLens = buffer.create(19)
				for Index = 0, HCLen - 1 do
					buffer.writeu8(CLLens, buffer.readu8(CL_ORDER, Index), buffer.readbits(Source, BitPos, 3))
					BitPos += 3
				end

				const CLLut, CLMax = BuildHuffman(CLLens, 19)
				const Total = HLit + HDist
				const CodeLens = buffer.create(Total)
				local Index = 0

				while Index < Total do
					local Symbol: number
					Symbol, BitPos = ReadSymbol(Source, BitPos, SourceBitEnd, CLLut, CLMax)

					if Symbol < 16 then
						buffer.writeu8(CodeLens, Index, Symbol)
						Index += 1
					elseif Symbol == 16 then
						if Index == 0 or BitPos + 2 > SourceBitEnd then
							error("Invalid code-length repeat")
						end
						const Repeat = buffer.readbits(Source, BitPos, 2) + 3
						BitPos += 2
						if Index + Repeat > Total then
							error("Code-length repeat is out of bounds")
						end
						const PreviousLength = buffer.readu8(CodeLens, Index - 1)
						buffer.fill(CodeLens, Index, PreviousLength, Repeat)
						Index += Repeat
					elseif Symbol == 17 then
						if BitPos + 3 > SourceBitEnd then
							error("Zero repeat is truncated")
						end
						const Repeat = buffer.readbits(Source, BitPos, 3) + 3
						BitPos += 3
						if Index + Repeat > Total then
							error("Zero repeat is out of bounds")
						end
						Index += Repeat
					elseif Symbol == 18 then
						if BitPos + 7 > SourceBitEnd then
							error("Long zero repeat is truncated")
						end
						const Repeat = buffer.readbits(Source, BitPos, 7) + 11
						BitPos += 7
						if Index + Repeat > Total then
							error("Long zero repeat is out of bounds")
						end
						Index += Repeat
					else
						error("Invalid code-length symbol")
					end
				end

				const LitLens = buffer.create(HLit)
				buffer.copy(LitLens, 0, CodeLens, 0, HLit)
				LitLut, LitMax = BuildHuffman(LitLens, HLit)

				const DistLens = buffer.create(HDist)
				buffer.copy(DistLens, 0, CodeLens, HLit, HDist)
				DistLut, DistMax = BuildHuffman(DistLens, HDist)
			end

			const LitMask = bit32.lshift(1, LitMax) - 1
			while true do
				if LitMax ~= 0
					and BitPos + LitMax * 2 <= SourceBitEnd
					and DestinationPos + 2 <= DestinationSize
				then
					const Bits = buffer.readbits(Source, BitPos, LitMax * 2)
					const FirstEntry = buffer.readu32(LitLut, bit32.band(Bits, LitMask) * 4)
					const FirstLength = FirstEntry // 65536
					const FirstSymbol = bit32.band(FirstEntry, 0xFFFF)

					if FirstLength ~= 0 and FirstSymbol < 256 then
						const SecondEntry = buffer.readu32(LitLut, bit32.band(bit32.rshift(Bits, FirstLength), LitMask) * 4)
						const SecondLength = SecondEntry // 65536
						const SecondSymbol = bit32.band(SecondEntry, 0xFFFF)

						buffer.writeu8(Destination, DestinationPos, FirstSymbol)
						DestinationPos += 1
						BitPos += FirstLength
						if SecondLength ~= 0 and SecondSymbol < 256 then
							buffer.writeu8(Destination, DestinationPos, SecondSymbol)
							DestinationPos += 1
							BitPos += SecondLength
						end
						continue
					end
				end
				local Symbol: number
				if LitMax ~= 0 and BitPos + LitMax <= SourceBitEnd then
					const Entry = buffer.readu32(LitLut, buffer.readbits(Source, BitPos, LitMax) * 4)
					const Length = Entry // 65536
					if Length == 0 then
						error("Invalid Huffman symbol")
					end
					Symbol = bit32.band(Entry, 0xFFFF)
					BitPos += Length
				else
					Symbol, BitPos = ReadSymbol(Source, BitPos, SourceBitEnd, LitLut, LitMax)
				end

				if Symbol < 256 then
					if DestinationPos >= DestinationSize then
						error("DEFLATE output exceeds expected size")
					end
					buffer.writeu8(Destination, DestinationPos, Symbol)
					DestinationPos += 1
				elseif Symbol == 256 then
					break
				elseif Symbol <= 285 then
					const LenIndex = Symbol - 257
					local Length = buffer.readu16(LEN_BASE, LenIndex * 2)
					const LenExtra = buffer.readu8(LEN_EXTRA, LenIndex)
					if BitPos + LenExtra > SourceBitEnd then
						error("DEFLATE length is truncated")
					end
					if LenExtra ~= 0 then
						Length += buffer.readbits(Source, BitPos, LenExtra)
						BitPos += LenExtra
					end

					local DistSymbol: number
					if DistMax ~= 0 and BitPos + DistMax <= SourceBitEnd then
						const Entry = buffer.readu32(DistLut, buffer.readbits(Source, BitPos, DistMax) * 4)
						const CodeLength = Entry // 65536
						if CodeLength == 0 then
							error("Invalid Huffman symbol")
						end
						DistSymbol = bit32.band(Entry, 0xFFFF)
						BitPos += CodeLength
					else
						DistSymbol, BitPos = ReadSymbol(Source, BitPos, SourceBitEnd, DistLut, DistMax)
					end
					if DistSymbol >= 30 then
						error("Invalid DEFLATE distance symbol")
					end

					local Distance = buffer.readu16(DIST_BASE, DistSymbol * 2)
					const DistExtra = buffer.readu8(DIST_EXTRA, DistSymbol)
					if BitPos + DistExtra > SourceBitEnd then
						error("DEFLATE distance is truncated")
					end
					if DistExtra ~= 0 then
						Distance += buffer.readbits(Source, BitPos, DistExtra)
						BitPos += DistExtra
					end

					if Distance == 0 or Distance > DestinationPos then
						error("Invalid DEFLATE distance")
					end
					if Length > DestinationSize - DestinationPos then
						error("Invalid DEFLATE length")
					end

					if Distance == 1 then
						buffer.fill(Destination, DestinationPos, buffer.readu8(Destination, DestinationPos - 1), Length)
					elseif Distance >= Length then
						buffer.copy(Destination, DestinationPos, Destination, DestinationPos - Distance, Length)
					else
						buffer.copy(Destination, DestinationPos, Destination, DestinationPos - Distance, Distance)
						local Copied = Distance
						while Copied < Length do
							const Count = math.min(Copied, Length - Copied)
							buffer.copy(Destination, DestinationPos + Copied, Destination, DestinationPos, Count)
							Copied += Count
						end
					end

					DestinationPos += Length
				else
					error("Invalid DEFLATE literal/length symbol")
				end
			end
		end
	end

	return BitPos, DestinationPos
end

@[native, checked] const function Inflate(Data: buffer, DecodedSize: number): buffer
	if DecodedSize < 0 or DecodedSize ~= math.floor(DecodedSize) then
		error("Invalid decoded size")
	end

	const Output = buffer.create(DecodedSize)
	const _, OutputPos = InflateInto(Data, 0, buffer.len(Data) * 8, Output, 0)
	if OutputPos ~= DecodedSize then
		error("DEFLATE output size mismatch")
	end
	return Output
end

type ArchiveEntry = {
	NameData: buffer,
	Data: buffer,
	Payload: buffer,
	Method: number,
	CRC: number,
	Size64: integer,
	CompressedSize64: integer,
	LocalOffset64: integer,
	ZipUncompressed: boolean,
	ZipCompressed: boolean,
	ZipOffset: boolean,
	LocalExtraLength: number,
	CentralExtraLength: number,
}

@[native, checked] const function NumberToInteger(Value: number, Label: string): integer
	if Value < 0 or Value ~= math.floor(Value) then
		error(`Invalid ZIP64 {Label}`)
	end

	const Result = integer.create(Value)
	if Result == nil then
		error(`ZIP64 {Label} cannot be represented exactly`)
	end
	return Result
end

@[native, checked] const function IntegerToNumber(Value: integer, Label: string): number
	const Result = integer.tonumber(Value)
	const RoundTrip = integer.create(Result)
	if RoundTrip == nil or RoundTrip ~= Value then
		error(`ZIP64 {Label} cannot be represented exactly`)
	end
	return Result
end

@[native, checked] const function FitsU16(Value: integer): boolean
	return integer.ult(Value, INTEGER_U16_SENTINEL)
end

@[native, checked] const function FitsU32(Value: integer): boolean
	return integer.ult(Value, INTEGER_U32_SENTINEL)
end

@[native, checked] const function WriteLegacyU16(Output: buffer, Offset: number, Value: integer)
	if FitsU16(Value) then
		buffer.writeu16(Output, Offset, integer.tonumber(Value))
	else
		buffer.writeu16(Output, Offset, 0xFFFF)
	end
end

@[native, checked] const function WriteLegacyU32(Output: buffer, Offset: number, Value: integer)
	if FitsU32(Value) then
		buffer.writeu32(Output, Offset, integer.tonumber(Value))
	else
		buffer.writeu32(Output, Offset, 0xFFFFFFFF)
	end
end

@[native, checked] const function WriteLocalZip64Extra(Output: buffer, Offset: number, Entry: ArchiveEntry)
	if Entry.LocalExtraLength == 0 then
		return
	end

	buffer.writeu16(Output, Offset, ZIP64_EXTRA_FIELD)
	buffer.writeu16(Output, Offset + 2, Entry.LocalExtraLength - 4)
	Offset += 4

	if Entry.ZipUncompressed then
		buffer.writeinteger(Output, Offset, Entry.Size64)
		Offset += 8
	end
	if Entry.ZipCompressed then
		buffer.writeinteger(Output, Offset, Entry.CompressedSize64)
	end
end

@[native, checked] const function WriteCentralZip64Extra(Output: buffer, Offset: number, Entry: ArchiveEntry)
	if Entry.CentralExtraLength == 0 then
		return
	end

	buffer.writeu16(Output, Offset, ZIP64_EXTRA_FIELD)
	buffer.writeu16(Output, Offset + 2, Entry.CentralExtraLength - 4)
	Offset += 4

	if Entry.ZipUncompressed then
		buffer.writeinteger(Output, Offset, Entry.Size64)
		Offset += 8
	end
	if Entry.ZipCompressed then
		buffer.writeinteger(Output, Offset, Entry.CompressedSize64)
		Offset += 8
	end
	if Entry.ZipOffset then
		buffer.writeinteger(Output, Offset, Entry.LocalOffset64)
	end
end

@[native, checked] const function Zip(Files: { [string]: buffer }, SearchDepth: number?): buffer
	const Names: { string } = {}
	for Name in Files do
		Names[#Names + 1] = Name
	end
	table.sort(Names)

	const Entries: { ArchiveEntry } = {}
	local LocalSize = 0
	local CentralSize = 0
	local HasZip64Entry = false

	for _, Name in Names do
		const Data = Files[Name]
		const NameData = buffer.fromstring(Name)
		const NameLength = buffer.len(NameData)
		if NameLength == 0 or NameLength > 0xFFFF then
			error("ZIP file name length is out of range")
		end

		const Compressed = Deflate(Data, SearchDepth)
		local Method = METHOD_DEFLATE
		local Payload = Compressed
		if buffer.len(Compressed) >= buffer.len(Data) then
			Method = METHOD_STORE
			Payload = Data
		end

		const Size64 = NumberToInteger(buffer.len(Data), "uncompressed size")
		const CompressedSize64 = NumberToInteger(buffer.len(Payload), "compressed size")
		const LocalOffset64 = NumberToInteger(LocalSize, "local header offset")
		const ZipUncompressed = not FitsU32(Size64)
		const ZipCompressed = not FitsU32(CompressedSize64)
		const ZipOffset = not FitsU32(LocalOffset64)
		const LocalExtraDataLength = (if ZipUncompressed then 8 else 0) + (if ZipCompressed then 8 else 0)
		const CentralExtraDataLength = LocalExtraDataLength + (if ZipOffset then 8 else 0)
		const LocalExtraLength = if LocalExtraDataLength == 0 then 0 else LocalExtraDataLength + 4
		const CentralExtraLength = if CentralExtraDataLength == 0 then 0 else CentralExtraDataLength + 4

		if LocalExtraLength ~= 0 or CentralExtraLength ~= 0 then
			HasZip64Entry = true
		end

		Entries[#Entries + 1] = {
			NameData = NameData,
			Data = Data,
			Payload = Payload,
			Method = Method,
			CRC = CRC32(Data),
			Size64 = Size64,
			CompressedSize64 = CompressedSize64,
			LocalOffset64 = LocalOffset64,
			ZipUncompressed = ZipUncompressed,
			ZipCompressed = ZipCompressed,
			ZipOffset = ZipOffset,
			LocalExtraLength = LocalExtraLength,
			CentralExtraLength = CentralExtraLength,
		}

		LocalSize += 30 + NameLength + LocalExtraLength + buffer.len(Payload)
		CentralSize += 46 + NameLength + CentralExtraLength
	end

	const EntryCount64 = NumberToInteger(#Entries, "entry count")
	const CentralOffset64 = NumberToInteger(LocalSize, "central directory offset")
	const CentralSize64 = NumberToInteger(CentralSize, "central directory size")
	const NeedsZip64EOCD = HasZip64Entry or not FitsU16(EntryCount64) or not FitsU32(CentralOffset64) or not FitsU32(CentralSize64)
	const TrailerSize = if NeedsZip64EOCD then 98 else 22
	const TotalSize = LocalSize + CentralSize + TrailerSize
	NumberToInteger(TotalSize, "archive size")

	const Output = buffer.create(TotalSize)
	local Position = 0

	for _, Entry in Entries do
		const NameLength = buffer.len(Entry.NameData)
		const CompressedSize = buffer.len(Entry.Payload)
		const NeedsZip64 = Entry.LocalExtraLength ~= 0

		buffer.writeu32(Output, Position, LOCAL_FILE_HEADER)
		buffer.writeu16(Output, Position + 4, if NeedsZip64 then VERSION_45 else VERSION_20)
		buffer.writeu16(Output, Position + 6, UTF8_FLAG)
		buffer.writeu16(Output, Position + 8, Entry.Method)
		buffer.writeu16(Output, Position + 10, 0)
		buffer.writeu16(Output, Position + 12, 0x0021)
		buffer.writeu32(Output, Position + 14, Entry.CRC)
		WriteLegacyU32(Output, Position + 18, Entry.CompressedSize64)
		WriteLegacyU32(Output, Position + 22, Entry.Size64)
		buffer.writeu16(Output, Position + 26, NameLength)
		buffer.writeu16(Output, Position + 28, Entry.LocalExtraLength)
		buffer.copy(Output, Position + 30, Entry.NameData, 0, NameLength)
		WriteLocalZip64Extra(Output, Position + 30 + NameLength, Entry)
		buffer.copy(Output, Position + 30 + NameLength + Entry.LocalExtraLength, Entry.Payload, 0, CompressedSize)
		Position += 30 + NameLength + Entry.LocalExtraLength + CompressedSize
	end

	const CentralOffset = Position
	for _, Entry in Entries do
		const NameLength = buffer.len(Entry.NameData)
		const NeedsZip64 = Entry.CentralExtraLength ~= 0

		buffer.writeu32(Output, Position, CENTRAL_DIRECTORY_ENTRY)
		buffer.writeu16(Output, Position + 4, if NeedsZip64 then VERSION_45 else VERSION_20)
		buffer.writeu16(Output, Position + 6, if NeedsZip64 then VERSION_45 else VERSION_20)
		buffer.writeu16(Output, Position + 8, UTF8_FLAG)
		buffer.writeu16(Output, Position + 10, Entry.Method)
		buffer.writeu16(Output, Position + 12, 0)
		buffer.writeu16(Output, Position + 14, 0x0021)
		buffer.writeu32(Output, Position + 16, Entry.CRC)
		WriteLegacyU32(Output, Position + 20, Entry.CompressedSize64)
		WriteLegacyU32(Output, Position + 24, Entry.Size64)
		buffer.writeu16(Output, Position + 28, NameLength)
		buffer.writeu16(Output, Position + 30, Entry.CentralExtraLength)
		buffer.writeu16(Output, Position + 32, 0)
		buffer.writeu16(Output, Position + 34, 0)
		buffer.writeu16(Output, Position + 36, 0)
		buffer.writeu32(Output, Position + 38, 0)
		WriteLegacyU32(Output, Position + 42, Entry.LocalOffset64)
		buffer.copy(Output, Position + 46, Entry.NameData, 0, NameLength)
		WriteCentralZip64Extra(Output, Position + 46 + NameLength, Entry)
		Position += 46 + NameLength + Entry.CentralExtraLength
	end

	if NeedsZip64EOCD then
		const Zip64EOCDOffset64 = NumberToInteger(Position, "ZIP64 EOCD offset")

		buffer.writeu32(Output, Position, ZIP64_END_OF_CENTRAL_DIRECTORY)
		buffer.writeinteger(Output, Position + 4, 44i)
		buffer.writeu16(Output, Position + 12, VERSION_45)
		buffer.writeu16(Output, Position + 14, VERSION_45)
		buffer.writeu32(Output, Position + 16, 0)
		buffer.writeu32(Output, Position + 20, 0)
		buffer.writeinteger(Output, Position + 24, EntryCount64)
		buffer.writeinteger(Output, Position + 32, EntryCount64)
		buffer.writeinteger(Output, Position + 40, CentralSize64)
		buffer.writeinteger(Output, Position + 48, CentralOffset64)
		Position += 56

		buffer.writeu32(Output, Position, ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR)
		buffer.writeu32(Output, Position + 4, 0)
		buffer.writeinteger(Output, Position + 8, Zip64EOCDOffset64)
		buffer.writeu32(Output, Position + 16, 1)
		Position += 20
	end

	buffer.writeu32(Output, Position, END_OF_CENTRAL_DIRECTORY)
	buffer.writeu16(Output, Position + 4, 0)
	buffer.writeu16(Output, Position + 6, 0)
	WriteLegacyU16(Output, Position + 8, EntryCount64)
	WriteLegacyU16(Output, Position + 10, EntryCount64)
	WriteLegacyU32(Output, Position + 12, CentralSize64)
	WriteLegacyU32(Output, Position + 16, CentralOffset64)
	buffer.writeu16(Output, Position + 20, 0)

	if CentralOffset ~= IntegerToNumber(CentralOffset64, "central directory offset") then
		error("Internal ZIP64 offset mismatch")
	end
	return Output
end

@[native, checked] const function ResolveZip64Extra(Data: buffer, ExtraStart: number, ExtraLength: number,
	Uncompressed32: number, Compressed32: number, LocalOffset32: number, DiskStart16: number): (integer, integer, integer, number)
	local Uncompressed64 = NumberToInteger(Uncompressed32, "uncompressed size")
	local Compressed64 = NumberToInteger(Compressed32, "compressed size")
	local LocalOffset64 = NumberToInteger(LocalOffset32, "local header offset")
	local DiskStart = DiskStart16
	const NeedUncompressed = Uncompressed32 == 0xFFFFFFFF
	const NeedCompressed = Compressed32 == 0xFFFFFFFF
	const NeedOffset = LocalOffset32 == 0xFFFFFFFF
	const NeedDisk = DiskStart16 == 0xFFFF

	if not NeedUncompressed and not NeedCompressed and not NeedOffset and not NeedDisk then
		return Uncompressed64, Compressed64, LocalOffset64, DiskStart
	end

	local Position = ExtraStart
	const ExtraEnd = ExtraStart + ExtraLength
	local Found = false

	while Position + 4 <= ExtraEnd do
		const HeaderID = buffer.readu16(Data, Position)
		const DataSize = buffer.readu16(Data, Position + 2)
		const FieldStart = Position + 4
		const FieldEnd = FieldStart + DataSize
		if FieldEnd > ExtraEnd then
			error("ZIP extra field is truncated")
		end

		if HeaderID == ZIP64_EXTRA_FIELD then
			local Cursor = FieldStart
			if NeedUncompressed then
				if Cursor + 8 > FieldEnd then error("ZIP64 uncompressed size is missing") end
				Uncompressed64 = buffer.readinteger(Data, Cursor)
				Cursor += 8
			end
			if NeedCompressed then
				if Cursor + 8 > FieldEnd then error("ZIP64 compressed size is missing") end
				Compressed64 = buffer.readinteger(Data, Cursor)
				Cursor += 8
			end
			if NeedOffset then
				if Cursor + 8 > FieldEnd then error("ZIP64 local header offset is missing") end
				LocalOffset64 = buffer.readinteger(Data, Cursor)
				Cursor += 8
			end
			if NeedDisk then
				if Cursor + 4 > FieldEnd then error("ZIP64 disk number is missing") end
				DiskStart = buffer.readu32(Data, Cursor)
			end
			Found = true
			break
		end

		Position = FieldEnd
	end

	if not Found then
		error("Required ZIP64 extra field not found")
	end
	return Uncompressed64, Compressed64, LocalOffset64, DiskStart
end

@[native, checked] const function Unzip(Data: buffer): { [string]: buffer }
	const Size = buffer.len(Data)
	if Size < 22 then
		error("ZIP file is truncated")
	end

	local EOCDPosition = -1
	const MinimumPosition = math.max(Size - 0x10015, 0)
	for SearchPosition = Size - 22, MinimumPosition, -1 do
		if buffer.readu32(Data, SearchPosition) == END_OF_CENTRAL_DIRECTORY then
			const CommentLength = buffer.readu16(Data, SearchPosition + 20)
			if SearchPosition + 22 + CommentLength == Size then
				EOCDPosition = SearchPosition
				break
			end
		end
	end
	if EOCDPosition < 0 then
		error("ZIP end of central directory not found")
	end

	const LegacyDisk = buffer.readu16(Data, EOCDPosition + 4)
	const LegacyCentralDisk = buffer.readu16(Data, EOCDPosition + 6)
	const LegacyEntriesOnDisk = buffer.readu16(Data, EOCDPosition + 8)
	const LegacyEntryCount = buffer.readu16(Data, EOCDPosition + 10)
	const LegacyCentralSize = buffer.readu32(Data, EOCDPosition + 12)
	const LegacyCentralOffset = buffer.readu32(Data, EOCDPosition + 16)

	local EntryCount64 = NumberToInteger(LegacyEntryCount, "entry count")
	local CentralSize64 = NumberToInteger(LegacyCentralSize, "central directory size")
	local CentralOffset64 = NumberToInteger(LegacyCentralOffset, "central directory offset")
	local CentralBoundary = EOCDPosition
	const NeedsZip64EOCD = LegacyEntriesOnDisk == 0xFFFF or LegacyEntryCount == 0xFFFF or LegacyCentralSize == 0xFFFFFFFF or LegacyCentralOffset == 0xFFFFFFFF

	if NeedsZip64EOCD then
		const LocatorPosition = EOCDPosition - 20
		if LocatorPosition < 0 or buffer.readu32(Data, LocatorPosition) ~= ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR then
			error("ZIP64 end of central directory locator not found")
		end
		if buffer.readu32(Data, LocatorPosition + 4) ~= 0 or buffer.readu32(Data, LocatorPosition + 16) ~= 1 then
			error("Multi-disk ZIP64 archives are not supported")
		end

		const Zip64Position64 = buffer.readinteger(Data, LocatorPosition + 8)
		const Zip64Position = IntegerToNumber(Zip64Position64, "EOCD offset")
		if Zip64Position + 56 > LocatorPosition or buffer.readu32(Data, Zip64Position) ~= ZIP64_END_OF_CENTRAL_DIRECTORY then
			error("Invalid ZIP64 end of central directory")
		end

		const RecordSize64 = buffer.readinteger(Data, Zip64Position + 4)
		if integer.lt(RecordSize64, 44i) then
			error("Invalid ZIP64 EOCD record size")
		end
		const RecordSize = IntegerToNumber(RecordSize64, "EOCD record size")
		if Zip64Position + 12 + RecordSize > LocatorPosition then
			error("ZIP64 EOCD record is truncated")
		end
		if buffer.readu32(Data, Zip64Position + 16) ~= 0 or buffer.readu32(Data, Zip64Position + 20) ~= 0 then
			error("Multi-disk ZIP64 archives are not supported")
		end

		const EntriesOnDisk64 = buffer.readinteger(Data, Zip64Position + 24)
		EntryCount64 = buffer.readinteger(Data, Zip64Position + 32)
		if EntriesOnDisk64 ~= EntryCount64 then
			error("Invalid ZIP64 entry count")
		end
		CentralSize64 = buffer.readinteger(Data, Zip64Position + 40)
		CentralOffset64 = buffer.readinteger(Data, Zip64Position + 48)
		CentralBoundary = Zip64Position
	else
		if LegacyDisk ~= 0 or LegacyCentralDisk ~= 0 or LegacyEntriesOnDisk ~= LegacyEntryCount then
			error("Multi-disk ZIP archives are not supported")
		end
	end

	const EntryCount = IntegerToNumber(EntryCount64, "entry count")
	const CentralSize = IntegerToNumber(CentralSize64, "central directory size")
	const CentralOffset = IntegerToNumber(CentralOffset64, "central directory offset")
	const CentralEnd = CentralOffset + CentralSize
	if CentralEnd > CentralBoundary or CentralOffset < 0 then
		error("Invalid ZIP central directory")
	end
	if EntryCount > CentralSize // 46 then
		error("Invalid ZIP64 entry count")
	end

	local Position = CentralOffset
	local Output: { [string]: buffer } = {}

	for _ = 1, EntryCount do
		if Position + 46 > CentralEnd or buffer.readu32(Data, Position) ~= CENTRAL_DIRECTORY_ENTRY then
			error("Invalid ZIP central directory entry")
		end

		const Flags = buffer.readu16(Data, Position + 8)
		const Method = buffer.readu16(Data, Position + 10)
		const ExpectedCRC = buffer.readu32(Data, Position + 16)
		const Compressed32 = buffer.readu32(Data, Position + 20)
		const Uncompressed32 = buffer.readu32(Data, Position + 24)
		const NameLength = buffer.readu16(Data, Position + 28)
		const ExtraLength = buffer.readu16(Data, Position + 30)
		const CommentLength = buffer.readu16(Data, Position + 32)
		const DiskStart16 = buffer.readu16(Data, Position + 34)
		const LocalOffset32 = buffer.readu32(Data, Position + 42)
		const EntryEnd = Position + 46 + NameLength + ExtraLength + CommentLength
		if EntryEnd > CentralEnd then
			error("ZIP central directory entry is truncated")
		end
		if bit32.band(Flags, 1) ~= 0 then
			error("Encrypted ZIP entries are not supported")
		end
		if Method ~= METHOD_STORE and Method ~= METHOD_DEFLATE then
			error(`Unsupported ZIP compression method: {Method}`)
		end

		const ExtraStart = Position + 46 + NameLength
		const Uncompressed64, Compressed64, LocalOffset64, DiskStart = ResolveZip64Extra(Data, ExtraStart, ExtraLength, Uncompressed32, Compressed32, LocalOffset32, DiskStart16)
		if DiskStart ~= 0 then
			error("Multi-disk ZIP64 archives are not supported")
		end

		const UncompressedSize = IntegerToNumber(Uncompressed64, "uncompressed size")
		const CompressedSize = IntegerToNumber(Compressed64, "compressed size")
		const LocalOffset = IntegerToNumber(LocalOffset64, "local header offset")
		if LocalOffset + 30 > Size or buffer.readu32(Data, LocalOffset) ~= LOCAL_FILE_HEADER then
			error("Invalid ZIP local file header")
		end

		const Name = buffer.readstring(Data, Position + 46, NameLength)
		const LocalNameLength = buffer.readu16(Data, LocalOffset + 26)
		const LocalExtraLength = buffer.readu16(Data, LocalOffset + 28)
		const DataStart = LocalOffset + 30 + LocalNameLength + LocalExtraLength
		if DataStart + CompressedSize > Size then
			error("ZIP file data is truncated")
		end

		const Value = buffer.create(UncompressedSize)
		if Method == METHOD_STORE then
			if Compressed64 ~= Uncompressed64 then
				error("Invalid stored ZIP entry size")
			end
			buffer.copy(Value, 0, Data, DataStart, CompressedSize)
		else
			local _, DestinationPos = InflateInto(Data, DataStart * 8, (DataStart + CompressedSize) * 8, Value, 0)
			if DestinationPos ~= UncompressedSize then
				error("ZIP entry size mismatch")
			end
		end

		if CRC32(Value) ~= ExpectedCRC then
			error(`ZIP CRC32 mismatch: {Name}`)
		end
		Output[Name] = Value
		Position = EntryEnd
	end

	return Output
end

return table.freeze({
	Zip = Zip,
	Unzip = Unzip,
	Deflate = Deflate,
	Inflate = Inflate,
	CRC32 = CRC32,
})
