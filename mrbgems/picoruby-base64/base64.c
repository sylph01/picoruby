#include <mrubyc.h>
#include <alloc.h>

const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void
c_base64_encode(mrbc_vm *vm, mrbc_value *v, int argc)
{
  size_t index = 0;
  size_t out_index = 0;
  size_t in_size, out_size;
  uint32_t n = 0;
  uint8_t n0, n1, n2, n3;

  mrbc_value input = GET_ARG(1);
  if (input.tt != MRBC_TT_STRING) {
    mrbc_raise(vm, MRBC_CLASS(TypeError), "wrong type of argument");
    return;
  }

  in_size  = input.string->size;
  out_size = (in_size + 2) / 3 * 4 + 1;
  uint8_t* output = mrbc_alloc(vm, out_size);
  uint8_t* data   = input.string->data;

  // create the main encoding
  for (index = 0; index < in_size; index += 3) {
    n = ((uint32_t)data[index]) << 16;

    if ((index + 1) < in_size)
      n += ((uint32_t)data[index + 1]) << 8;

    if ((index + 2) < in_size)
      n += data[index + 2];

    n0 = (uint8_t)(n >> 18) & 63;
    n1 = (uint8_t)(n >> 12) & 63;
    n2 = (uint8_t)(n >> 6)  & 63;
    n3 = (uint8_t)n         & 63;

    // generate 2 chars from 1 byte
    output[out_index++] = base64chars[n0];
    output[out_index++] = base64chars[n1];
    // if 2nd byte, generate 3rd char
    if(index + 1 < in_size)
      output[out_index++] = base64chars[n2];
    // if 3rd byte, generate 4th char
    if(index + 2 < in_size)
      output[out_index++] = base64chars[n3];
  }

  // create padding
  int padding = in_size % 3;
  if (padding > 0) {
    for (; padding < 3; padding++) {
      output[out_index++] = '=';
    }
  }

  mrbc_value ret = mrbc_string_new(vm, output, out_size - 1); // remove the termination byte at the end
  mrbc_free(vm, output);
  SET_RETURN(ret);
}

unsigned char convert(unsigned char n) {
  if (n >= 0x30 && n <= 0x39) {
    return n - 0x30;
  } else if (n >= 0x41 && n <= 0x46) {
    return n - 55; // 0x41(A) = 65 should return 10
  } else if (n >= 0x61 && n <= 0x66) {
    return n - 87; // 0x61(a) = 97 should return 10
  } else {
    return 0;
  }
}

/*
static void
c_base64_decode(mrbc_vm *vm, mrbc_value *v, int argc)
{
  size_t index = 0;
  size_t in_size, out_size;
  uint8_t n0, n1;

  mrbc_value input = GET_ARG(1);
  if (input.tt != MRBC_TT_STRING) {
    mrbc_raise(vm, MRBC_CLASS(TypeError), "wrong type of argument");
    return;
  }

  in_size  = input.string->size;
  out_size = in_size / 2;
  // Base16 in RFC4648 assumes input size to be even,
  // but Ruby's pack('H*') treats as if there is a 0 at the end
  if (in_size % 2 == 1) {
    out_size += 1;
  }
  uint8_t* output = mrbc_alloc(vm, out_size);

  for (index = 0; index < out_size; index++) {
    n0 = convert(input.string->data[index * 2]);
    if (index * 2 + 1 < in_size) {
      n1 = convert(input.string->data[index * 2 + 1]);
    } else {
      n1 = 0;
    }
    output[index] = (n0 << 4) + n1;
  }

  mrbc_value ret = mrbc_string_new(vm, output, out_size);
  mrbc_free(vm, output);
  SET_RETURN(ret);
}
*/

void
mrbc_base64_init(void)
{
  mrbc_class *class_Base64 = mrbc_define_class(0, "Base64", mrbc_class_object);

  mrbc_define_method(0, class_Base64, "encode64", c_base64_encode);
  // mrbc_define_method(0, class_Base64, "decode64", c_base64_decode);
}