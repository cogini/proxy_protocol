defmodule ProxyProtocolTest do
  use ExUnit.Case, async: true

  test "format_family_v1/1" do
    assert ProxyProtocol.format_family_v1({192, 168, 1, 1}) == "TCP4"
  end

  describe "format_header_v1/4" do
    test "Handles IPv4" do
      src_addr = {192, 168, 1, 1}
      src_port = 10_000
      dst_addr = {10, 0, 0, 1}
      dst_port = 443
      header = ProxyProtocol.format_header_v1(src_addr, src_port, dst_addr, dst_port)
      assert IO.iodata_to_binary(header) == "PROXY TCP4 192.168.1.1 10.0.0.1 10000 443\r\n"
    end
  end

  describe "format_header_v2/4" do
    test "Handles IPv4" do
      src_addr = {192, 168, 1, 1}
      src_port = 10_000
      dst_addr = {10, 0, 0, 1}
      dst_port = 443
      header = ProxyProtocol.format_header_v2(src_addr, src_port, dst_addr, dst_port)

      # expected_header = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x02]
      expected_header = [
        13,
        10,
        13,
        10,
        0,
        13,
        10,
        81,
        85,
        73,
        84,
        10,
        "!",
        <<17>>,
        <<0, 12>>,
        <<192, 168, 1, 1>>,
        <<10, 0, 0, 1>>,
        <<39, 16>>,
        <<1, 187>>
      ]

      <<proxy_protocol_version::4, proxy_protocol_command::4>> = "!"
      <<address_family::4, transport_protocol::4>> = <<17>>
      assert proxy_protocol_version == 2
      assert proxy_protocol_command == 1
      assert address_family == 1
      assert transport_protocol == 1
      assert header == expected_header
    end
  end
end
