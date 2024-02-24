defmodule ProxyProtocol do
  @moduledoc """
  https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
  """

  @doc "Create text header"
  @spec format_header_v1(
          :inet.ip_address(),
          :inet.port_number(),
          :inet.ip_address(),
          :inet.port_number()
        ) :: iodata()
  def format_header_v1(src_addr, src_port, dst_addr, dst_port) do
    [
      "PROXY ",
      format_family_v1(src_addr),
      0x20,
      :inet.ntoa(src_addr),
      0x20,
      :inet.ntoa(dst_addr),
      0x20,
      Integer.to_string(src_port),
      0x20,
      Integer.to_string(dst_port),
      0x0D,
      0x0A
    ]
  end

  @doc "Create header family string based on type of address"
  @spec format_family_v1(:inet.ip_address()) :: binary()
  def format_family_v1({_, _, _, _}), do: "TCP4"
  def format_family_v1({_, _, _, _, _, _, _, _}), do: "TCP6"

  @doc "Create binary header"
  @spec format_header_v2(
          :inet.ip_address(),
          :inet.port_number(),
          :inet.ip_address(),
          :inet.port_number()
        ) :: iodata()
  def format_header_v2(src_addr, src_port, dst_addr, dst_port) do
    # proxy protocol version
    proxy_protocol_version = 2
    # PROXY
    proxy_protocol_command = 1

    address_family = format_family_v2(src_addr)
    # STREAM
    transport_protocol = 1

    [
      # signature
      0x0D,
      0x0A,
      0x0D,
      0x0A,
      0x00,
      0x0D,
      0x0A,
      0x51,
      0x55,
      0x49,
      0x54,
      0x0A,
      <<proxy_protocol_version::4, proxy_protocol_command::4>>,
      <<address_family::4, transport_protocol::4>>,
      format_length_v2(address_family),
      format_addr_v2(src_addr),
      format_addr_v2(dst_addr),
      format_port_v2(src_port),
      format_port_v2(dst_port)
    ]
  end

  @doc "Create header family based on type of address"
  @spec format_family_v2(:inet.ip_address()) :: integer()
  def format_family_v2({_, _, _, _}), do: 1
  def format_family_v2({_, _, _, _, _, _, _, _}), do: 2

  def format_addr_v2({b1, b2, b3, b4}) do
    <<b1::8, b2::8, b3::8, b4::8>>
  end

  def format_addr_v2({b1, b2, b3, b4, b5, b6, b7, b8}) do
    <<b1::8, b2::8, b3::8, b4::8, b5::8, b6::8, b7::8, b8::8>>
  end

  def format_port_v2(port), do: <<port::big-integer-size(16)>>

  def format_length_v2(1), do: <<12::big-integer-size(16)>>
  def format_length_v2(2), do: <<36::big-integer-size(16)>>
end
