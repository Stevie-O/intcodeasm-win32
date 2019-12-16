
#include "pch.h"
#include <tclap/CmdLine.h>
#include <tclap/SwitchArg.h>
#include <tclap/ValueArg.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <vector>

namespace intcode {

	using memory_cell = std::int_fast64_t;
	using memory = std::vector<memory_cell>;

	namespace type_support {

		template <typename T> struct type_tag { using type = T; };

		template <typename V> struct variant_types {};

		template <typename... Ts> struct variant_types<std::variant<Ts...>> {
			using type = std::tuple<type_tag<Ts>...>;
		};

	} // namespace type_support

	namespace util {

		std::string read_stream(std::istream &in) {
			std::string result;
			std::copy(std::istreambuf_iterator<char>{in},
				std::istreambuf_iterator<char>{}, std::back_inserter(result));
			return result;
		}

		template <typename Container,
			std::enable_if_t<std::is_convertible_v<
			std::string, typename Container::value_type>,
			int> = 0>
			Container split(std::string_view string, std::regex const &separator) {
			Container tokens;

			using token_iter =
				std::regex_token_iterator<std::string_view::const_iterator>;
			std::copy(token_iter{ string.begin(), string.end(), separator, -1 },
				token_iter{}, std::back_inserter(tokens));

			return tokens;
		}

		template <typename Container, typename Separator>
		std::ostream &join_to_stream(std::ostream &os, Container &&c, Separator &&sep) {
			bool first = true;
			for (auto const &value : c) {
				if (!first)
					os << sep;
				os << value;
				first = false;
			}
			return os;
		}

		std::intmax_t string_to_intmax(std::string const &s) {
			// NOTE that strtoimax clamps the value to the maximum range, and there
			// is nothing we can do about that. The errno == ERANGE case is useless
			// because the call may have been successful and the error value may have been
			// left by a previous call.
			char *end_ptr;
			std::intmax_t result = std::strtoimax(s.c_str(), &end_ptr, 10);
			if (end_ptr != s.data() + s.size())
				throw std::invalid_argument{ "Failed to parse as intmax_t: " + s };
			return result;
		}

		template <typename Integer, std::enable_if_t<std::is_integral_v<Integer> &&
			std::is_signed_v<Integer>,
			int> = 0>
			Integer string_to_integer(std::string const &s) {
			auto const i = string_to_intmax(s);
			if (i < std::numeric_limits<Integer>::min() ||
				i > std::numeric_limits<Integer>::max())
				throw std::range_error{ "Value out of range: " + std::to_string(i) };
			return static_cast<Integer>(i);
		}

		void upcase(std::string &s) {
			std::transform(s.begin(), s.end(), s.begin(),
				[](unsigned char c) -> char { return std::toupper(c); });
		}

	} // namespace util

	namespace parser {

		struct parse_error : std::runtime_error {
			using runtime_error::runtime_error;
		};

		template <typename Container,
			std::enable_if_t<std::is_convertible_v<
			memory_cell, typename Container::value_type>,
			int> = 0>
			Container parse_int_list(std::string_view input) {
			auto tokens = util::split<std::vector<std::string>>(input, std::regex{ "," });

			Container content;

			std::regex const num_regex{ "\\s*([+-]?[0-9]+)\\s*" };
			std::transform(tokens.begin(), tokens.end(), std::back_inserter(content),
				[&](std::string const &t) {
				std::smatch m;
				if (std::regex_match(t, m, num_regex)) {
					return util::string_to_integer<memory_cell>(m[1]);
				}
				else {
					throw parse_error{ "Invalid token: " + t };
				}
			});

			return content;
		}

	} // namespace parser

	struct execution_error : std::runtime_error {
		using runtime_error::runtime_error;
	};

	namespace io {
		struct input_pipe {
			virtual ~input_pipe() = default;
			virtual memory_cell read() = 0;
		};

		struct output_pipe {
			virtual ~output_pipe() = default;
			virtual void write(memory_cell) = 0;
		};
	} // namespace io

	class virtual_machine final {
	public:
		explicit virtual_machine(memory m) : mem{ std::move(m) } {}

		memory_cell fetch_at_ip() {
			auto index = ip++;
			if (index >= mem.size())
				return 0;
			else
				return mem.at(index);
		}

		void reset_ip() { ip = 0; }

		std::size_t current_ip() const { return ip; }

		memory_cell load(memory_cell const address) const {
			auto index = address_to_index(address);
			if (index < mem.size())
				return mem[index];
			else
				return 0;
		}

		void store(memory_cell const address, memory_cell const value) {
			auto index = address_to_index(address);
			if (index == std::numeric_limits<std::size_t>::max())
				throw execution_error{ "Required memory size not representable as size_t" };

			if (index >= mem.size()) {
				if (memory_limit && index >= *memory_limit)
					throw execution_error{
						"Required memory size exceeds configured memory limit" };
				mem.resize(index + 1);
			}

			mem[index] = value;
		}

		void jump(memory_cell const address) { ip = address_to_index(address); }

		memory_cell get_base_pointer() const { return base_pointer; }

		void adjust_base_pointer(memory_cell const offset) { base_pointer += offset; }

		memory_cell input() {
			if (!indev)
				throw execution_error{ "No input device set" };
			return indev->read();
		}

		void output(memory_cell const value) {
			if (!outdev)
				throw execution_error{ "No output device set" };
			outdev->write(value);
		}

		void set_output_device(std::shared_ptr<io::output_pipe> pipe) {
			outdev = std::move(pipe);
		}

		void set_input_device(std::shared_ptr<io::input_pipe> pipe) {
			indev = std::move(pipe);
		}

		void set_memory_limit(std::optional<std::size_t> const l) {
			memory_limit = l;
		}

		memory const &get_memory() const { return mem; }

	private:
		std::size_t address_to_index(memory_cell const address) const {
			if (address < 0)
				throw execution_error{ "Negative address: " + std::to_string(address) };
			if constexpr (sizeof(memory_cell) > sizeof(std::size_t)) {
				if (address >
					static_cast<memory_cell>(std::numeric_limits<std::size_t>::max()))
					throw execution_error{ "Address too large: " + std::to_string(address) };
			}
			auto index = static_cast<std::size_t>(address);
			return index;
		}

		memory mem;
		memory_cell base_pointer = 0;
		std::size_t ip = 0;
		std::optional<std::size_t> memory_limit;
		std::shared_ptr<io::output_pipe> outdev;
		std::shared_ptr<io::input_pipe> indev;
	};

	namespace io {

		class cin_pipe : public input_pipe {
		public:
			memory_cell read() override {
				memory_cell value;
				std::cerr << "The program is expecting input: " << std::flush;
				if (!(std::cin >> value))
					throw execution_error{ "No input available" };
				return value;
			}
		};

		class cout_pipe : public output_pipe {
		public:
			void write(memory_cell const value) override { std::cout << value << '\n'; }
		};

		class deque_pipe : public input_pipe, public output_pipe {
		public:
			deque_pipe() {}

			explicit deque_pipe(std::deque<memory_cell> initial_content)
				: queue{ std::move(initial_content) } {}

			memory_cell read() override {
				if (queue.empty())
					throw std::runtime_error{ "Read from empty pipe" };
				auto const v = queue.front();
				queue.pop_front();
				return v;
			}

			void write(memory_cell const v) override { queue.push_back(v); }

			std::deque<memory_cell> const &get_queue() const & { return queue; }
			void set_queue(std::deque<memory_cell> q) { queue = std::move(q); }

		private:
			std::deque<memory_cell> queue;
		};

		class file_output_pipe : public output_pipe {
		public:
			explicit file_output_pipe(std::string const &filename) : file{ filename } {
				if (!file.is_open())
					throw std::runtime_error{ "Unable to open output file " + filename };
			}

			void write(memory_cell const value) override {
				if (!first)
					file << ',';
				file << value;
				first = false;
			}

		private:
			std::ofstream file;
			bool first = true;
		};

	} // namespace io

	enum class operand_mode { address, immediate, relative_address };

	struct operand final {
		operand_mode mode;
		memory_cell value;
	};

	std::ostream &operator<<(std::ostream &os, operand const op) {
		switch (op.mode) {
		case operand_mode::immediate:
			os << op.value;
			break;
		case operand_mode::address:
			os << '[' << op.value << ']';
			break;
		case operand_mode::relative_address:
			os << "[BP ";
			if (op.value < 0)
				os << "- " << -op.value;
			else
				os << "+ " << op.value;
			os << ']';
			break;
		}
		return os;
	}

	namespace vm_util {
		memory_cell load_operand(virtual_machine const &vm, operand const op) {
			switch (op.mode) {
			case operand_mode::immediate:
				return op.value;
			case operand_mode::address:
				return vm.load(op.value);
			case operand_mode::relative_address:
				return vm.load(op.value + vm.get_base_pointer());
			}
		}

		void store_operand(virtual_machine &vm, operand const op,
			memory_cell const value) {
			switch (op.mode) {
			case operand_mode::immediate:
				throw execution_error{ "Cannot store to immediate operand" };
			case operand_mode::address:
				vm.store(op.value, value);
				break;
			case operand_mode::relative_address:
				vm.store(op.value + vm.get_base_pointer(), value);
				break;
			}
		}
	} // namespace vm_util

	namespace instructions {
		struct adder final {
			static memory_cell compute(memory_cell const left, memory_cell const right) {
				return left + right;
			}
			static void output_mnemonic(std::ostream &os) { os << "ADD"; }
		};

		struct multiplier final {
			static memory_cell compute(memory_cell const left, memory_cell const right) {
				return left * right;
			}
			static void output_mnemonic(std::ostream &os) { os << "MUL"; }
		};

		template <memory_cell Opcode, typename Operator> class basic_binary_operation {
		public:
			static constexpr memory_cell opcode = Opcode;
			static constexpr std::size_t operand_count = 3;

			basic_binary_operation(operand src1, operand src2, operand dst)
				: src_op_left{ src1 }, src_op_right{ src2 }, dst_op{ dst } {}

			void execute(virtual_machine &vm) const {
				memory_cell const left_input = vm_util::load_operand(vm, src_op_left);
				memory_cell const right_input = vm_util::load_operand(vm, src_op_right);
				memory_cell const result = Operator::compute(left_input, right_input);
				vm_util::store_operand(vm, dst_op, result);
			}

			static std::ostream &output_mnemonic(std::ostream &os) {
				Operator::output_mnemonic(os);
				return os;
			}

			std::array<operand, operand_count> operands() const {
				return { src_op_left, src_op_right, dst_op };
			}

		private:
			operand src_op_left;
			operand src_op_right;
			operand dst_op;
		};

		using add = basic_binary_operation<1, adder>;
		using multiply = basic_binary_operation<2, multiplier>;

		class input final {
		public:
			static constexpr memory_cell opcode = 3;
			static constexpr std::size_t operand_count = 1;

			explicit input(operand dst) : dst_op{ dst } {}

			void execute(virtual_machine &vm) const {
				vm_util::store_operand(vm, dst_op, vm.input());
			}

			static std::ostream &output_mnemonic(std::ostream &os) { return os << "INP"; }

			std::array<operand, operand_count> operands() const { return { dst_op }; }

		private:
			operand dst_op;
		};

		class output final {
		public:
			static constexpr memory_cell opcode = 4;
			static constexpr std::size_t operand_count = 1;

			explicit output(operand src) : src_op{ src } {}

			void execute(virtual_machine &vm) const {
				vm.output(vm_util::load_operand(vm, src_op));
			}

			static std::ostream &output_mnemonic(std::ostream &os) { return os << "OUT"; }

			std::array<operand, operand_count> operands() const { return { src_op }; }

		private:
			operand src_op;
		};

		struct condition_nonzero final {
			static bool met(memory_cell const value) { return value != 0; }
			static void output_mnemonic_fragment(std::ostream &os) { os << "NZ"; }
		};

		struct condition_zero final {
			static bool met(memory_cell const value) { return value == 0; }
			static void output_mnemonic_fragment(std::ostream &os) { os << "Z"; }
		};

		struct condition_less final {
			static bool met(memory_cell const left, memory_cell const right) {
				return left < right;
			}
			static void output_mnemonic_fragment(std::ostream &os) { os << "LT"; }
		};

		struct condition_equal final {
			static bool met(memory_cell const left, memory_cell const right) {
				return left == right;
			}
			static void output_mnemonic_fragment(std::ostream &os) { os << "EQ"; }
		};

		template <memory_cell Opcode, typename Condition> class conditional_jump final {
		public:
			static constexpr memory_cell opcode = Opcode;
			static constexpr std::size_t operand_count = 2;

			explicit conditional_jump(operand cond, operand tgt)
				: condition{ cond }, target{ tgt } {}

			void execute(virtual_machine &vm) const {
				if (Condition::met(vm_util::load_operand(vm, condition)))
					vm.jump(vm_util::load_operand(vm, target));
			}

			static std::ostream &output_mnemonic(std::ostream &os) {
				Condition::output_mnemonic_fragment(os << 'J');
				return os;
			}

			std::array<operand, operand_count> operands() const {
				return { condition, target };
			}

		private:
			operand condition;
			operand target;
		};

		template <memory_cell Opcode, typename Condition> class comparison final {
		public:
			static constexpr memory_cell opcode = Opcode;
			static constexpr std::size_t operand_count = 3;

			explicit comparison(operand left, operand right, operand dest)
				: left{ left }, right{ right }, destination{ dest } {}

			void execute(virtual_machine &vm) const {
				memory_cell const res = Condition::met(vm_util::load_operand(vm, left),
					vm_util::load_operand(vm, right))
					? 1
					: 0;
				vm_util::store_operand(vm, destination, res);
			}

			static std::ostream &output_mnemonic(std::ostream &os) {
				Condition::output_mnemonic_fragment(os << "CMP");
				return os;
			}

			std::array<operand, operand_count> operands() const {
				return { left, right, destination };
			}

		private:
			operand left;
			operand right;
			operand destination;
		};

		using jump_if_nonzero = conditional_jump<5, condition_nonzero>;
		using jump_if_zero = conditional_jump<6, condition_zero>;
		using compare_less = comparison<7, condition_less>;
		using compare_equal = comparison<8, condition_equal>;

		class adjust_relative_base final {
		public:
			static constexpr memory_cell opcode = 9;
			static constexpr std::size_t operand_count = 1;

			explicit adjust_relative_base(operand base_offset)
				: base_offset{ base_offset } {}

			void execute(virtual_machine &vm) const {
				vm.adjust_base_pointer(vm_util::load_operand(vm, base_offset));
			}

			static std::ostream &output_mnemonic(std::ostream &os) { return os << "ABP"; }

			std::array<operand, operand_count> operands() const { return { base_offset }; }

		private:
			operand base_offset;
		};
	} // namespace instructions

	using instruction =
		std::variant<instructions::add, instructions::multiply, instructions::input,
		instructions::output, instructions::jump_if_nonzero,
		instructions::jump_if_zero, instructions::compare_less,
		instructions::compare_equal,
		instructions::adjust_relative_base>;

	namespace executor {
		std::ostream &disassemble_instruction(std::ostream &os,
			instruction const &inst) {
			std::visit(
				[&](auto const &inst) {
				util::join_to_stream(inst.output_mnemonic(os) << ' ', inst.operands(),
					", ");
			},
				inst);
			return os;
		}

		operand_mode decode_operand_mode(memory_cell const value) {
			switch (value) {
			case 0:
				return operand_mode::address;
			case 1:
				return operand_mode::immediate;
			case 2:
				return operand_mode::relative_address;
			default:
				throw execution_error{ "Invalid operand mode: " + std::to_string(value) };
			}
		}

		template <std::size_t Count>
		std::array<memory_cell, Count> fetch_operand_values(virtual_machine &vm) {
			std::array<memory_cell, Count> result;
			for (std::size_t i = 0; i < Count; ++i)
				result.at(i) = vm.fetch_at_ip();
			return result;
		}

		// nullopt means HALT
		std::optional<instruction> fetch_instruction(virtual_machine &vm) {
			memory_cell const head = vm.fetch_at_ip();
			if (head < 0 || head > 99999)
				throw execution_error{ "Invalid instruction head: " + std::to_string(head) };

			memory_cell const opcode = head % 100;
			std::array<operand_mode, 3> operand_modes{
				decode_operand_mode((head / 100) % 10),
				decode_operand_mode((head / 1000) % 10),
				decode_operand_mode((head / 10000) % 10) };

			if (opcode == 99)
				return std::nullopt;

			std::optional<instruction> inst;
			std::apply(
				[&](auto... tags) {
				(
					[&](auto tag) {
					using inst_type = typename decltype(tag)::type;
					if (inst_type::opcode == opcode) {
						if (inst) {
							throw std::logic_error{
								"Bug: Multiple instructions with opcode " +
								std::to_string(opcode) };
						}
						if constexpr (inst_type::operand_count == 0) {
							inst = inst_type{};
						}
						else {
							static_assert(inst_type::operand_count <= 3);
							auto operand_values =
								fetch_operand_values<inst_type::operand_count>(vm);
							std::array<operand, inst_type::operand_count> operands;
							for (std::size_t i = 0; i < inst_type::operand_count; ++i)
								operands.at(i) =
								operand{ operand_modes.at(i), operand_values.at(i) };
							inst = std::make_from_tuple<inst_type>(operands);
						}
					}
				}(tags),
					...);
			},
				typename type_support::variant_types<instruction>::type{});

			if (inst)
				return *inst;
			else
				throw execution_error{ "Invalid opcode: " + std::to_string(opcode) };
		}

		// false means HALT
		bool execute_next(virtual_machine &vm) {
			if (auto inst = fetch_instruction(vm)) {
				std::visit([&](auto const inst) { inst.execute(vm); }, *inst);
				return true;
			}
			else {
				return false;
			}
		}

		// false means HALT
		bool disassemble_next(virtual_machine &vm, std::ostream &os) {
			os << vm.current_ip() << ": ";
			if (auto inst = fetch_instruction(vm)) {
				std::visit(
					[&](auto const inst) { disassemble_instruction(os, inst) << '\n'; },
					*inst);
				return true;
			}
			else {
				os << "HALT\n";
				return false;
			}
		}

		// false means HALT
		bool execute_and_disassemble_next(virtual_machine &vm, std::ostream &os) {
			os << vm.current_ip() << ": ";
			if (auto inst = fetch_instruction(vm)) {
				std::visit(
					[&](auto const inst) {
					disassemble_instruction(os, inst) << '\n';
					inst.execute(vm);
				},
					*inst);
				return true;
			}
			else {
				os << "HALT\n";
				return false;
			}
		}
	} // namespace executor

	class assembler final {
	public:
		struct assembly_error : std::runtime_error {
			using runtime_error::runtime_error;
		};

		assembler() {
			std::apply(
				[&](auto... tags) {
				(
					[&](auto tag) {
					using instruction_type = typename decltype(tag)::type;
					std::ostringstream str;
					instruction_type::output_mnemonic(str);
					mnemonic_map.emplace(
						str.str(),
						instruction_descriptor{ instruction_type::opcode,
											   instruction_type::operand_count });
				}(tags),
					...);
			},
				typename type_support::variant_types<instruction>::type{});
		}

		memory parse_assembly(std::istream &is) {
			std::regex const blank_line_regex{ "\\s*(;.*)?" };
			std::regex const line_regex{ "\\s*([^\\s;]([^;]*[^\\s;])?)\\s*(;.*)?" };

			parse_context context;

			std::string line;
			while (std::getline(is, line)) {
				++context.lineno;
				if (std::regex_match(line, blank_line_regex))
					continue;
				std::smatch line_match;
				if (std::regex_match(line, line_match, line_regex)) {
					parse_line(context, line_match[1].str());
				}
				else {
					throw_line_error(context, "Malformatted line: " + line);
				}
			}

			apply_relocations(context);

			return std::move(context).mem;
		}

	private:
		static constexpr memory_cell canary_value = 11198;

		struct instruction_descriptor final {
			memory_cell opcode;
			std::size_t operand_count;
		};

		struct relocation final {
			std::size_t address;
			std::string symbol;
		};

		struct parse_context final {
			memory mem;
			std::vector<relocation> relocations;
			std::unordered_map<std::string, std::size_t> labels;
			std::size_t lineno{};
		};

		[[noreturn]] void throw_line_error(parse_context &context,
			std::string const &message) {
			throw assembly_error{ "Line " + std::to_string(context.lineno) + ": " +
								 message };
		}

		memory_cell encode_operand_mode(operand_mode const value) {
			switch (value) {
			case operand_mode::address:
				return 0;
			case operand_mode::immediate:
				return 1;
			case operand_mode::relative_address:
				return 2;
			}
		}

		std::variant<std::string, memory_cell>
			parse_constant_or_relocation(parse_context &context, std::string const &raw) {
			std::regex const number_regex{ "[+-]?[0-9]+" };
			std::regex const identifier_regex{ "[a-zA-Z_][a-zA-Z0-9_]*" };
			if (std::regex_match(raw, number_regex)) {
				return util::string_to_integer<memory_cell>(raw);
			}
			else if (std::regex_match(raw, identifier_regex)) {
				return raw;
			}
			else {
				throw_line_error(context, "Expected number or identifier: " + raw);
			}
		}

		void parse_and_push_constant_or_relocation(parse_context &context,
			std::string const &raw) {
			auto const value = parse_constant_or_relocation(context, raw);
			if (std::holds_alternative<std::string>(value)) {
				context.relocations.push_back(
					relocation{ context.mem.size(), std::get<std::string>(value) });
				context.mem.push_back(canary_value);
			}
			else {
				context.mem.push_back(std::get<memory_cell>(value));
			}
		}

		void label_current_address(parse_context &context,
			std::string const &symbol) {
			auto const[it, was_inserted] =
				context.labels.emplace(symbol, context.mem.size());
			if (!was_inserted)
				throw_line_error(context, "Duplicate label " + symbol);
		}

		void parse_data_definition(parse_context &context,
			std::string const &raw_arg) {
			std::regex const di_arg_regex{
				"\\s*(([a-zA-Z_][a-zA-Z_0-9]*)\\s*:\\s*)?(.*\\S)\\s*" };
			std::smatch m;
			if (!std::regex_match(raw_arg, m, di_arg_regex))
				throw_line_error(context, "Malformed argument to DI: " + raw_arg);
			if (m[2].length() > 0)
				label_current_address(context, m[2].str());
			auto values = util::split<std::vector<std::string>>(m[3].str(), std::regex{ "\\s*,\\s*" });
			std::regex const di_value_regex{ "\\s*(?:(\\S+)|0*([1-9][0-9]*)\\s+[Dd][Uu][Pp]\\s*\\(\\s*(\\S+)\\s*\\))\\s*" };
			for (auto v : values) {
				std::smatch m2;
				if (!std::regex_match(v, m2, di_value_regex))
					throw_line_error(context, "Malformed argument to DI: " + v);
				if (m2[1].matched) {
					parse_and_push_constant_or_relocation(context, m2[1].str());
				}
				else {
					auto count = util::string_to_integer<int>(m2[2]);
					for (int i = 0; i < count; i++) {
						parse_and_push_constant_or_relocation(context, m2[3].str());
					}
				}
			}
			//parse_and_push_constant_or_relocation(context, m[3].str());
		}

		operand_mode parse_operand(parse_context &context, std::string const &raw) {
			std::regex const over_regex{ "\\s*(([a-zA-Z_][a-zA-Z_0-9]*)\\s*:\\s*)?"
										"([^\\s](.*[^\\s])?)\\s*" };
			std::regex const relative_operand_regex{
				"\\[\\s*[Bb][Pp]\\s*([+-])\\s*([0-9]+)\\s*\\]" };
			std::regex const absolute_operand_regex{
				"\\[\\s*([+-]?[0-9]+|[a-zA-Z_][a-zA-Z0-9_]*)\\s*\\]" };
			std::regex const immediate_operand_regex{
				"[+-]?[0-9]+|[a-zA-Z_][a-zA-Z0-9_]*" };

			std::smatch over_match;
			if (!std::regex_match(raw, over_match, over_regex))
				throw_line_error(context, "Malformatted operand: " + raw);
			if (over_match[2].length() > 0)
				label_current_address(context, over_match[2].str());
			std::string raw_operand = over_match[3].str();

			std::smatch m;
			if (std::regex_match(raw_operand, m, relative_operand_regex)) {
				auto const value = parse_constant_or_relocation(context, m[2].str());
				if (!std::holds_alternative<memory_cell>(
					value)) // Should be impossible due to regex
					throw_line_error(context, "Cannot relocate relative operands");
				auto number = std::get<memory_cell>(value);
				if ("-" == m[1])
					number = -number;
				context.mem.push_back(number);
				return operand_mode::relative_address;
			}
			else if (std::regex_match(raw_operand, m, absolute_operand_regex)) {
				parse_and_push_constant_or_relocation(context, m[1].str());
				return operand_mode::address;
			}
			else if (std::regex_match(raw_operand, m, immediate_operand_regex)) {
				parse_and_push_constant_or_relocation(context, raw_operand);
				return operand_mode::immediate;
			}
			else {
				throw_line_error(context, "Malformed operand: " + raw_operand);
			}
		}

		void parse_instruction(parse_context &context, std::string const &mnemonic,
			std::vector<std::string> const &raw_operands) {
			if (auto it = mnemonic_map.find(mnemonic); it != mnemonic_map.end()) {
				instruction_descriptor const &instruction_descriptor = it->second;
				if (instruction_descriptor.operand_count != raw_operands.size()) {
					throw_line_error(
						context, "Invalid number of operands to " + mnemonic +
						" instruction, expects " +
						std::to_string(instruction_descriptor.operand_count));
				}
				std::size_t const instruction_address = context.mem.size();
				context.mem.push_back(instruction_descriptor.opcode);
				memory_cell operand_mode_multiplier = 100;
				for (std::string const &raw_operand : raw_operands) {
					operand_mode const opmode = parse_operand(context, raw_operand);
					context.mem.at(instruction_address) +=
						operand_mode_multiplier * encode_operand_mode(opmode);
					operand_mode_multiplier *= 10;
				}
			}
			else {
				throw_line_error(context, "Invalid instruction mnemonic: " + mnemonic);
			}
		}

		void parse_line(parse_context &context, std::string const &line) {
			std::regex const label_only_regex{ "([a-zA-Z_][a-zA-Z_0-9]*)\\s*:" };
			std::regex const assembly_regex{
				"(([a-zA-Z_][a-zA-Z_0-9]*)\\s*:\\s*)?" // Label (optional)
				"([a-zA-Z][a-zA-Z0-9]*)"               // The instruction mnemonic
				"\\s*([^\\s](.*[^\\s])?)?"             // Operand list (optional)
			};
			std::regex const comma_regex{ "," };

			std::smatch m;
			if (std::regex_match(line, m, label_only_regex)) {
				label_current_address(context, m[1].str());
			}
			else if (std::regex_match(line, m, assembly_regex)) {
				if (m[2].length() > 0) {
					label_current_address(context, m[2].str());
				}
				std::string mnemonic = m[3].str();
				util::upcase(mnemonic);
				if ("DI" == mnemonic) {
					if (m[4].length() <= 0)
						throw_line_error(context, "DI requires argument");
					parse_data_definition(context, m[4].str());
				}
				else if ("HALT" == mnemonic) {
					if (m[4].length() > 0)
						throw_line_error(context, "HALT does not accept arguments");
					context.mem.push_back(99);
				}
				else {
					std::vector<std::string> raw_operands;
					if (m[4].length() > 0)
						raw_operands =
						util::split<std::vector<std::string>>(m[4].str(), comma_regex);
					parse_instruction(context, mnemonic, raw_operands);
				}
			}
			else {
				throw_line_error(context, "Malformed line: " + line);
			}
		}

		void apply_relocations(parse_context &context) {
			for (relocation const &reloc : context.relocations) {
				if (auto it = context.labels.find(reloc.symbol);
					it != context.labels.end()) {
					context.mem.at(reloc.address) = it->second;
				}
				else {
					throw assembly_error{ "Relocation at address " +
										 std::to_string(reloc.address) +
										 " references undefined label " + reloc.symbol };
				}
			}
		}

		std::unordered_map<std::string, instruction_descriptor> mnemonic_map;
	};

} // namespace intcode

#ifdef SELF_TEST
namespace self_test {
	struct test_failure : std::logic_error {
		using logic_error::logic_error;
	};

	class vm_test_case final {
	public:
		explicit vm_test_case(std::string const &source_code)
			: vm{ intcode::parser::parse_int_list<intcode::memory>(source_code) } {
			vm.set_memory_limit(std::size_t{ 640 }
			<< 10); // Ought to be enough for everybody
			auto output_dev = std::make_shared<intcode::io::deque_pipe>();
			vm.set_output_device(output_dev);
			while (intcode::executor::execute_next(vm))
				;
			output = output_dev->get_queue();
		}

		vm_test_case(std::string const &source_code,
			std::deque<intcode::memory_cell> inp)
			: vm{ intcode::parser::parse_int_list<intcode::memory>(source_code) } {
			vm.set_memory_limit(std::size_t{ 640 }
			<< 10); // Ought to be enough for everybody
			auto input_dev = std::make_shared<intcode::io::deque_pipe>();
			input_dev->set_queue(std::move(inp));
			auto output_dev = std::make_shared<intcode::io::deque_pipe>();
			vm.set_output_device(output_dev);
			vm.set_input_device(input_dev);
			while (intcode::executor::execute_next(vm))
				;
			output = output_dev->get_queue();
		}

		void assert_memory(intcode::memory_cell const address,
			intcode::memory_cell const expected_content) {
			auto actual = vm.load(address);
			if (expected_content != actual) {
				throw test_failure{ "Expected " + std::to_string(expected_content) +
								   " at address " + std::to_string(address) + ", found " +
								   std::to_string(actual) };
			}
		}

		void assert_ip(std::size_t const expected) {
			auto actual = vm.current_ip();
			if (expected != actual) {
				throw test_failure{ "Expected IP to be at " + std::to_string(expected) +
								   " but it's at " + std::to_string(actual) };
			}
		}

		void assert_output(std::deque<intcode::memory_cell> const &expected) {
			if (expected.size() != output.size()) {
				throw test_failure{ "Expected " + std::to_string(expected.size()) +
								   " output values, got " +
								   std::to_string(output.size()) };
			}
			auto expected_it = expected.begin();
			auto expected_end = expected.end();
			auto actual_it = output.begin();
			auto actual_end = output.end();
			while (actual_it != actual_end && expected_it != expected_end) {
				if (*expected_it != *actual_it) {
					throw test_failure{ "Expected an output of " +
									   std::to_string(*expected_it) + ", got " +
									   std::to_string(*actual_it) };
				}
				++actual_it;
				++expected_it;
			}
		}

	private:
		std::deque<intcode::memory_cell> output;
		intcode::virtual_machine vm;
	};

	class asm_test_case final {
	public:
		explicit asm_test_case(std::string const &source_code) {
			std::istringstream stream{ source_code };
			intcode::assembler assem;
			mem = assem.parse_assembly(stream);
		}

		void assert_memory(intcode::memory const &expected) {
			if (expected.size() != mem.size()) {
				std::ostringstream stream;
				output_mem_inequality_message(stream, expected)
					<< "; size differs: Expected " << expected.size() << ", actual "
					<< mem.size();
				throw test_failure{ stream.str() };
			}
			std::size_t const size = expected.size();
			for (std::size_t i = 0; i < size; ++i) {
				if (expected.at(i) != mem.at(i)) {
					std::ostringstream stream;
					output_mem_inequality_message(stream, expected)
						<< "; mismatch at " << i << ": Expected " << expected.at(i)
						<< ", actual " << mem.at(i);
					throw test_failure{ stream.str() };
				}
			}
		}

	private:
		std::ostream &output_mem_inequality_message(std::ostream &os,
			intcode::memory const &expected) {
			os << "[";
			intcode::util::join_to_stream(os, expected, ",");
			os << "] != [";
			intcode::util::join_to_stream(os, mem, ",");
			os << "]";
			return os;
		}

		intcode::memory mem;
	};

	void run() {
		{
			vm_test_case c{ "1101,5,6,5,99,0" };
			c.assert_ip(5);
			c.assert_memory(5, 11);
		}
		{
			vm_test_case c{ "1,5,6,5,99,13,55" };
			c.assert_memory(5, 68);
			c.assert_memory(6, 55);
		}
		{
			vm_test_case c{ "1102,-4,10,5,99,0" };
			c.assert_memory(5, -40);
		}
		{
			vm_test_case c{ "3,3,99,0", {77} };
			c.assert_memory(3, 77);
		}
		{
			vm_test_case c{ "104,66,99" };
			c.assert_output({ 66 });
		}
		{
			vm_test_case c{ "3,0, 3,1, 3,2, 2,0,1,1, 1,2,1,0, 4,0, 99", {4, 7, 15} };
			c.assert_ip(17);
			c.assert_output({ 43 });
		}
		{
			vm_test_case c{ "1105, 0, 7,  101, 30, 15, 15,  1105, 1, 14,  101, 300, 15, "
						   "15,  99,  3" };
			c.assert_ip(15);
			c.assert_memory(15, 33);
		}
		{
			vm_test_case c{ "1106, 0, 7,  101, 30, 15, 15,  1106, 1, 14,  101, 300, 15, "
						   "15,  99,  3" };
			c.assert_ip(15);
			c.assert_memory(15, 303);
		}
		{
			vm_test_case c{ "1107, 66, 77, 9,  1107, 77, 66, 10,  99,  2, 2" };
			c.assert_memory(9, 1);
			c.assert_memory(10, 0);
		}
		{
			vm_test_case c{ "1108, 66, 77, 9,  1108, 66, 66, 10,  99,  2, 2" };
			c.assert_memory(9, 0);
			c.assert_memory(10, 1);
		}
		{
			vm_test_case c{ "109, 17,  21101, 13, 0, 0,  21101, 6, 0, 1,  22202, 0, 1, "
						   "0,  204, 0,  99" };
			c.assert_output({ 13 * 6 });
		}
		{
			vm_test_case c{ "109,1,204,-1,1001,100,1,100,1008,100,16,101,1006,101,0,99" };
			c.assert_output({ 109, 1, 204, -1, 1001, 100, 1, 100, 1008, 100, 16, 101,
							 1006, 101, 0, 99 });
		}
		{
			vm_test_case c{ "1102,34915192,34915192,9,4,9,104,1125899906842624,99,0" };
			c.assert_output(
				{ intcode::memory_cell{34915192} *intcode::memory_cell{34915192},
				 1125899906842624 });
		}
		{
			asm_test_case c{ R"ASM(
				; Should parse just fine with comments
				add 5, 7, [0]   ; Add constants 5 and 7 and store result at address 0
				out [0]         ; Output value at address 0
				halt            ; Stop executing
			)ASM" };
			c.assert_memory({ 1101, 5, 7, 0, 4, 0, 99 });
		}
		{
			asm_test_case c{ R"ASM(
				mul 5, 7, [foo]
				out [foo]
				halt
				foo: di 789
			)ASM" };
			c.assert_memory({ 1102, 5, 7, 7, 4, 7, 99, 789 });
		}
		{
			asm_test_case c{ R"ASM(
				abp data_start
				loop_start:
				cmplt 0, [bp+0], [bp+1]
				jnz [bp+1], loop_start
				halt

				data_start:
				di 65535
			)ASM" };
			c.assert_memory({ 109, 10, 22107, 0, 0, 1, 1205, 1, 2, 99, 65535 });
		}
		{
			asm_test_case c{ R"ASM(
				jz value:16, end
				add -1, [value], [value]
				end: halt
			)ASM" };
			c.assert_memory({ 1106, 16, 7, 101, -1, 1, 1, 99 });
		}
		{
			asm_test_case c{ R"ASM(
				inp [55]
				out [55]
				halt
			)ASM" };
			c.assert_memory({ 3, 55, 4, 55, 99 });
		}
		{
			asm_test_case c{ R"ASM(
				halt
				standalone_label:
				di 0
				line_label: di 1
				di argument_label:2
				di argument_label
				di line_label
				di standalone_label
			)ASM" };
			c.assert_memory({ 99, 0, 1, 2, 3, 2, 1 });
		}
	}
} // namespace self_test
#endif

struct options_error : std::runtime_error {
	using runtime_error::runtime_error;
};

struct options final {
	struct file_tag final {
		std::string filename;
	};
	struct direct_tag final {
		std::string content;
	};
	struct assemble_file_tag final {
		std::string filename;
	};
	struct null_tag final {};

	std::variant<direct_tag, file_tag, assemble_file_tag> source;
	bool execute;
	bool disassemble;
	std::optional<std::size_t> memory_limit;
	std::variant<null_tag, direct_tag, file_tag> input;
	std::variant<null_tag, file_tag> output;
	std::optional<std::string> dump_to_file;
};

void real_main(options const &options) {
	intcode::memory mem = std::visit(
		[](auto const &source_option) {
		using source_option_type = std::decay_t<decltype(source_option)>;
		if constexpr (std::is_same_v<options::file_tag, source_option_type>) {
			std::ifstream source_file{ source_option.filename };
			if (!source_file.is_open())
				throw std::runtime_error{ "Unable to open source file " +
										 source_option.filename };
			std::cerr << "Reading Intcode from " << source_option.filename
				<< std::endl;
			return intcode::parser::parse_int_list<intcode::memory>(
				intcode::util::read_stream(source_file));
		}
		else if constexpr (std::is_same_v<options::direct_tag,
			source_option_type>) {
			return intcode::parser::parse_int_list<intcode::memory>(
				source_option.content);
		}
		else if constexpr (std::is_same_v<options::assemble_file_tag,
			source_option_type>) {
			std::ifstream source_file{ source_option.filename };
			if (!source_file.is_open())
				throw std::runtime_error{ "Unable to open source file " +
										 source_option.filename };
			std::cerr << "Assembling Intcode from " << source_option.filename
				<< std::endl;
			intcode::assembler assembler;
			return assembler.parse_assembly(source_file);
		}
	},
		options.source);

	if (options.execute)
		std::cerr << "Executing:\n";
	if (options.disassemble)
		std::cerr << "Disassembly:\n";

	intcode::virtual_machine vm{ mem };
	vm.set_memory_limit(options.memory_limit);

	std::visit(
		[&](auto const &input_option) {
		using input_option_type = std::decay_t<decltype(input_option)>;
		if constexpr (std::is_same_v<options::file_tag, input_option_type>) {
			std::ifstream input_file{ input_option.filename };
			if (!input_file.is_open())
				throw std::runtime_error{ "Unable to open input file " +
										 input_option.filename };
			std::cerr << "Reading program input from " << input_option.filename
				<< std::endl;
			vm.set_input_device(std::make_shared<intcode::io::deque_pipe>(
				intcode::parser::parse_int_list<std::deque<intcode::memory_cell>>(
					intcode::util::read_stream(input_file))));
		}
		else if constexpr (std::is_same_v<options::direct_tag,
			input_option_type>) {
			vm.set_input_device(std::make_shared<intcode::io::deque_pipe>(
				intcode::parser::parse_int_list<std::deque<intcode::memory_cell>>(
					input_option.content)));
		}
		else if constexpr (std::is_same_v<options::null_tag,
			input_option_type>) {
			vm.set_input_device(std::make_shared<intcode::io::cin_pipe>());
		}
	},
		options.input);

	std::visit(
		[&](auto const &output_option) {
		using output_option_type = std::decay_t<decltype(output_option)>;
		if constexpr (std::is_same_v<options::file_tag, output_option_type>) {
			vm.set_output_device(std::make_shared<intcode::io::file_output_pipe>(
				output_option.filename));
		}
		else if constexpr (std::is_same_v<options::null_tag,
			output_option_type>) {
			vm.set_output_device(std::make_shared<intcode::io::cout_pipe>());
		}
	},
		options.output);

	while (true) {
		if (options.execute) {
			if (options.disassemble) {
				if (!intcode::executor::execute_and_disassemble_next(vm, std::cerr))
					break;
				std::cerr << std::flush;
			}
			else {
				if (!intcode::executor::execute_next(vm))
					break;
			}
		}
		else if (options.disassemble) {
			if (!intcode::executor::disassemble_next(vm, std::cerr))
				break;
			std::cerr << std::flush;
		}
		else {
			break;
		}
	}

	if (options.dump_to_file) {
		std::ofstream dump_file{ *options.dump_to_file };
		if (!dump_file.is_open())
			throw std::runtime_error{ "Unable to open dump file: " +
									 *options.dump_to_file };
		std::cerr << "Writing memory dump to " << *options.dump_to_file
			<< std::endl;
		intcode::util::join_to_stream(dump_file, vm.get_memory(), ",");
		dump_file.close();
	}
}

int main(int argc, char **argv) {
#ifdef SELF_TEST
	std::cerr << "Running self-test ... " << std::flush;
	self_test::run();
	std::cerr << "Passed.\n";
#endif

	TCLAP::CmdLine cmd{ "Advent of Code 2019 Intcode virtual machine" };
	TCLAP::ValueArg<std::string> source_file_arg{
		"s",
		"source-file",
		"File to read the Intcode from as a comma-separated list of integers.",
		false,
		"",
		"filename",
		cmd };
	TCLAP::ValueArg<std::string> source_string_arg{
		"S",
		"source-string",
		"The Intcode as a comma-separated list of integers.",
		false,
		"",
		"intcode",
		cmd };
	TCLAP::ValueArg<std::string> assembly_file_arg{
		"a",
		"assemble",
		"File to read assembly source code from. Use -m (without -x) to write"
		" the assembled Intcode to a file.",
		false,
		"",
		"filename",
		cmd };
	TCLAP::ValueArg<std::string> input_file_arg{
		"i",
		"input-file",
		"File to read the program input from, as a comma-separated list of "
		"integers."
		" If no input option is specified, the program input is read from STDIN "
		"as"
		" whitespace-separated integers.",
		false,
		"",
		"filename",
		cmd };
	TCLAP::ValueArg<std::string> input_string_arg{
		"I",
		"input-string",
		"The program input as a comma-separated list of integers.",
		false,
		"",
		"program input",
		cmd };
	TCLAP::ValueArg<std::string> output_file_arg{
		"o",
		"output-file",
		"File to write the program output to, as a comma-separated list of "
		"integers."
		" If no output option is specified, the program output is written to "
		"STDOUT"
		" as whitespace-separated integers.",
		false,
		"",
		"filename",
		cmd };
	TCLAP::ValueArg<std::string> dump_file_arg{
		"m",
		"dump",
		"File to write memory dump to, as a comma-separated list of integers."
		" If execution is enabled, the dump is written after the program has"
		" halted.",
		false,
		"",
		"filename",
		cmd };
	TCLAP::SwitchArg execute_arg{ "x", "execute", "Execute code", cmd };
	TCLAP::SwitchArg disassemble_arg{
		"d", "disassemble",
		"Show disassembly, affected by self-modifying code if also executing",
		cmd };
	TCLAP::SwitchArg unlimited_memory_arg{
		"u", "unlimited-memory",
		"Remove the default memory limit. This allows the VM to consume an "
		"unlimited amount of memory."
		" Use with care.",
		cmd };
	TCLAP::ValueArg<std::size_t> memory_limit_arg{
		"l",
		"memory-limit",
		"Specify the VM memory limit. The default is 256M.",
		false,
		256,
		"megabytes",
		cmd };

	cmd.parse(argc, argv);

	options options;

	try {

		if (auto source_file_name = source_file_arg.getValue();
			!source_file_name.empty()) {
			if (!source_string_arg.getValue().empty() ||
				!assembly_file_arg.getValue().empty())
				throw options_error{ "-s, -S and -a are mutually exclusive" };
			options.source = options::file_tag{ std::move(source_file_name) };
		}
		else if (auto source_string = source_string_arg.getValue();
			!source_string.empty()) {
			if (!assembly_file_arg.getValue().empty())
				throw options_error{ "-s, -S and -a are mutually exclusive" };
			options.source = options::direct_tag{ std::move(source_string) };
		}
		else if (auto assembly_file_name = assembly_file_arg.getValue();
			!assembly_file_name.empty()) {
			options.source =
				options::assemble_file_tag{ std::move(assembly_file_name) };
		}
		else {
			throw options_error{ "One of -s, -S or -a must supply the Intcode" };
		}

		if (auto input_file_name = input_file_arg.getValue();
			!input_file_name.empty()) {
			if (!input_string_arg.getValue().empty())
				throw options_error{ "-i and -I are mutually exclusive" };
			options.input = options::file_tag{ std::move(input_file_name) };
		}
		else if (auto input_string = input_string_arg.getValue();
			!input_string.empty()) {
			options.input = options::direct_tag{ std::move(input_string) };
		}
		else {
			options.input = options::null_tag{};
		}

		if (auto output_file_name = output_file_arg.getValue();
			!output_file_name.empty()) {
			options.output = options::file_tag{ std::move(output_file_name) };
		}
		else {
			options.output = options::null_tag{};
		}

		if (auto dump_file_name = dump_file_arg.getValue();
			!dump_file_name.empty()) {
			options.dump_to_file = dump_file_name;
		}
		else {
			options.dump_to_file = std::nullopt;
		}

		options.execute = execute_arg.getValue();
		options.disassemble = disassemble_arg.getValue();
		if (unlimited_memory_arg.getValue())
			options.memory_limit = std::nullopt;
		else
			options.memory_limit =
			(memory_limit_arg.getValue() << 20) / sizeof(intcode::memory_cell);

		real_main(options);

	}
	catch (std::exception const &e) {
		std::cerr << "FATAL: " << e.what() << '\n';
		return EXIT_FAILURE;
	}
}