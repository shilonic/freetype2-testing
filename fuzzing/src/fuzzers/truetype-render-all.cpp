// truetype-render-all.cpp
//
//   Self-contained, single-file TrueType render fuzz harness.
//   All code from the harness framework (targets, iterators, visitors,
//   utils) is inlined here so that `LLVMFuzzerTestOneInput' and every
//   function it calls down to the FreeType library API live in one
//   translation unit.
//
//   NOTE: This file intentionally duplicates code that normally lives in
//   separate .h/.cpp files in the fuzzing/src/ tree.
//
// Original copyright 2018-2019 by
// Armin Hasitzka, David Turner, Robert Wilhelm, and Werner Lemberg.
//
// This file is part of the FreeType project, and may only be used,
// modified, and distributed under the terms of the FreeType project
// license, LICENSE.TXT.  By continuing to use, modify, or distribute
// this file you indicate that you have read the license and
// understand and accept it fully.


// ===========================================================================
// Standard / system headers
// ===========================================================================

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

// ===========================================================================
// FreeType headers
// ===========================================================================

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H
#include FT_DRIVER_H
#include FT_AUTOHINTER_H
#include FT_MODULE_H
#include FT_FONT_FORMATS_H
#include FT_MULTIPLE_MASTERS_H
#include FT_ERRORS_H

// ftobjs.h is a FreeType-internal header needed only for get_ft_memory().
// When building against a system-installed FreeType it may not be available.
#ifdef FT2_BUILD_LIBRARY
#include <freetype/internal/ftobjs.h>
#endif

// ===========================================================================
// Libarchive (optional – only needed for tar-archive inputs)
// ===========================================================================

#ifdef HAVE_ARCHIVE
#include <archive.h>
#include <archive_entry.h>
#endif


// ===========================================================================
// Logging (compile-time switchable, defaults to no-op)
// ===========================================================================

#ifdef LOGGER_GLOG
#include <glog/logging.h>
#else
#define LOG( a )       ; if ( 0 ) std::cout
#define LOG_IF( a, b ) ; if ( 0 ) std::cout
#endif

#define LOG_FT_ERROR( fn_name, error )                                  \
  LOG_IF( ERROR, error != 0 )                                           \
  << fn_name << " failed: "                                             \
  << "0x" << std::setfill( '0' ) << std::setw( 2 ) << std::hex << error \
  << " (" << FT_Error_String( error ) << ")"

#define WARN_ABOUT_IGNORED_VALUES( available, capped, name )  \
  do                                                          \
  {                                                           \
    LOG_IF( WARNING, (available) > (capped) )                 \
      << "aborted early: "                                    \
      << ( (available) - (capped) )                           \
      << " " << name << " ignored";                           \
  } while (0)


// ===========================================================================
// Forward declarations (all in namespace freetype)
// ===========================================================================

struct archive;

namespace freetype
{
  // ---- noncopyable --------------------------------------------------------

  class noncopyable
  {
  protected:
    noncopyable()  = default;
    ~noncopyable() = default;
    noncopyable( const noncopyable& ) = delete;
    noncopyable& operator=( const noncopyable& ) = delete;
  };

  // ---- Unique pointer helpers ---------------------------------------------

  typedef std::unique_ptr<struct archive,
                          int( * )( struct archive* )>  Unique_Archive;

  typedef std::unique_ptr<FT_FaceRec,
                          decltype( FT_Done_Face )*>  Unique_FT_Face;

  typedef std::unique_ptr<FT_GlyphRec,
                          decltype( FT_Done_Glyph )*>  Unique_FT_Glyph;

  template<typename T, typename... Args>
  std::unique_ptr<T>
  make_unique( Args&&...  args )
  {
    return std::unique_ptr<T>( new T( std::forward<Args>( args )... ) );
  }

  Unique_FT_Face   make_unique_face ( FT_Face  face   = nullptr );
  Unique_FT_Glyph  make_unique_glyph( FT_Glyph glyph  = nullptr );
  Unique_FT_Glyph  copy_unique_glyph( const Unique_FT_Glyph&  glyph );
  Unique_FT_Glyph  get_unique_glyph_from_face( const Unique_FT_Face& face );
  bool glyph_has_reasonable_size( const Unique_FT_Glyph& glyph,
                                  FT_Pos reasonable_pixels );
  bool glyph_has_reasonable_size( const Unique_FT_Glyph& glyph,
                                  FT_Pos reasonable_pixels,
                                  FT_Pos reasonable_width,
                                  FT_Pos reasonable_height );
  bool glyph_has_reasonable_work_size  ( const Unique_FT_Glyph& glyph );
  bool glyph_has_reasonable_render_size( const Unique_FT_Glyph& glyph );

  // ---- Forward declarations for classes -----------------------------------

  class TarReader;
  class FaceLoader;
  class FaceVisitor;
  class GlyphVisitor;
  class GlyphRenderIterator;
  class GlyphLoadIterator;
  class FacePrepIterator;
  class FaceLoadIterator;
  class FacePrepIteratorBitmaps;
  class FacePrepIteratorOutlines;
  class FacePrepIteratorMultipleMasters;
  class FaceVisitorAutohinter;
  class FaceVisitorLoadGlyphs;
  class FaceVisitorLoadGlyphsBitmaps;
  class FaceVisitorLoadGlyphsOutlines;
  class FaceVisitorRenderGlyphs;
  class FaceVisitorSubGlyphs;
  class FuzzTarget;
  class FaceFuzzTarget;
  class TrueTypeRenderFuzzTarget;

}  // namespace freetype


// ###########################################################################
//
//  SECTION 1 — Utility implementations
//
// ###########################################################################

namespace freetype
{

  // ---- make_unique_face / make_unique_glyph --------------------------------

  Unique_FT_Face
  make_unique_face( FT_Face  face )
  {
    return Unique_FT_Face( face, FT_Done_Face );
  }

  Unique_FT_Glyph
  make_unique_glyph( FT_Glyph  glyph )
  {
    return Unique_FT_Glyph( glyph, FT_Done_Glyph );
  }

  Unique_FT_Glyph
  copy_unique_glyph( const Unique_FT_Glyph&  glyph )
  {
    FT_Error  error;
    FT_Glyph  raw_glyph;

    error = FT_Glyph_Copy( glyph.get(), &raw_glyph );
    LOG_FT_ERROR( "FT_Glyph_Copy", error );

    return make_unique_glyph( error == 0 ? raw_glyph : nullptr );
  }

  Unique_FT_Glyph
  get_unique_glyph_from_face( const Unique_FT_Face&  face )
  {
    FT_Error  error;
    FT_Glyph  glyph;

    error = FT_Get_Glyph( face->glyph, &glyph );
    LOG_FT_ERROR( "FT_Get_Glyph", error );

    return make_unique_glyph( error == 0 ? glyph : nullptr );
  }

  bool
  glyph_has_reasonable_size( const Unique_FT_Glyph&  glyph,
                             FT_Pos                  reasonable_pixels )
  {
    return glyph_has_reasonable_size( glyph, reasonable_pixels, 0, 0 );
  }

  bool
  glyph_has_reasonable_size( const Unique_FT_Glyph&  glyph,
                             FT_Pos                  reasonable_pixels,
                             FT_Pos                  reasonable_width,
                             FT_Pos                  reasonable_height )
  {
    static const auto  POS_MAX = std::numeric_limits<FT_Pos>::max();

    FT_BBox  box;
    FT_Pos   pixels;
    FT_Pos   width;
    FT_Pos   height;

    if ( glyph == nullptr )
    {
      LOG( WARNING ) << "glyph is null";
      return false;
    }

    (void) FT_Glyph_Get_CBox( glyph.get(), FT_GLYPH_BBOX_PIXELS, &box );

    width  = std::abs( box.xMin - box.xMax );
    height = std::abs( box.yMin - box.yMax );

    LOG( INFO ) << "glyph size: " << width << " x " << height << " px\n";

    if ( ( reasonable_width  > 0 && width  > reasonable_width  ) ||
         ( reasonable_height > 0 && height > reasonable_height ) )
    {
      LOG( WARNING ) << "glyph is beyond reasonable size";
      return false;
    }

    pixels = width > 0 && POS_MAX / width < height ? POS_MAX : width * height;

    if ( reasonable_pixels > 0 && pixels > reasonable_pixels )
    {
      LOG( WARNING ) << "glyph is beyond reasonable size";
      return false;
    }

    return true;
  }

  bool
  glyph_has_reasonable_work_size( const Unique_FT_Glyph&  glyph )
  {
    return glyph_has_reasonable_size( glyph, 32767 * 32767 );
  }

  bool
  glyph_has_reasonable_render_size( const Unique_FT_Glyph&  glyph )
  {
    return glyph_has_reasonable_size( glyph, 2500 * 2500, 10000, 5000 );
  }

}  // namespace freetype


// ###########################################################################
//
//  SECTION 2 — TarReader
//
// ###########################################################################

namespace freetype
{

  class TarReader
    : private noncopyable
  {
  public:

    typedef std::vector<std::vector<FT_Byte>>  Files;

    TarReader( Files&  files )
      : files( files ) {}

    bool
    extract_data( const uint8_t*  data,
                  size_t          size )
    {
#ifdef HAVE_ARCHIVE
      Unique_Archive  archive( archive_read_new(),
                               archive_read_free );

      struct archive_entry*  entry;

      if ( archive == nullptr )
      {
        LOG( ERROR ) << "archive_read_new failed\n";
        return false;
      }

      if ( archive_read_support_format_tar( archive.get() ) != ARCHIVE_OK )
      {
        LOG( ERROR ) << "archive_read_support_format_tar failed: "
                     << archive_error_string( archive.get() ) << "\n";
        return false;
      }

      if ( archive_read_open_memory(
             archive.get(),
             const_cast<void*>( reinterpret_cast<const void*>( data ) ),
             size ) != ARCHIVE_OK )
      {
        LOG( ERROR ) << "archive_read_open_memory failed: "
                     << archive_error_string( archive.get() ) << "\n";
        return false;
      }

      while ( archive_read_next_header( archive.get(),
                                        &entry ) == ARCHIVE_OK )
      {
        int  r;

        const FT_Byte*  buffer;
        size_t          buffer_size;
        la_int64_t      offset;

        std::vector<FT_Byte>  entry_data;

        LOG( INFO ) << "extracting: "
                    << archive_entry_pathname( entry )
                    << "\n";

        for (;;)
        {
          r = archive_read_data_block(
                archive.get(),
                reinterpret_cast<const void**>( &buffer ),
                &buffer_size,
                &offset );

          if ( r == ARCHIVE_EOF )
            break;

          if ( r != ARCHIVE_OK )
          {
            LOG( ERROR ) << "archive_read_data_block failed: " << r << "\n";
            return false;
          }

          (void) entry_data.insert( entry_data.end(),
                                    buffer,
                                    buffer + buffer_size );
        }

        (void) files.emplace_back( entry_data );
      }
#else
      (void) data;
      (void) size;
      LOG( ERROR ) << "tar archive support not compiled in\n";
      return false;
#endif
      return true;
    }

  private:

    Files&  files;
  };

}  // namespace freetype


// ###########################################################################
//
//  SECTION 3 — FaceLoader
//
// ###########################################################################

namespace freetype
{

  class FaceLoader
    : private noncopyable
  {
  public:

    enum class FontFormat : unsigned char
    {
      NONE,
      BDF,
      CID_TYPE_1,
      CFF,
      PCF,
      PFR,
      TRUETYPE,
      TYPE_1,
      TYPE_42,
      WINDOWS_FNT
    };

    FaceLoader()
      : tarreader( files ) {}

    void
    set_supported_font_format( FontFormat  format )
    {
      supported_font_format = format;

      switch ( format )
      {
      case FontFormat::NONE:        supported_font_format_string = "None";        break;
      case FontFormat::BDF:         supported_font_format_string = "BDF";         break;
      case FontFormat::CID_TYPE_1:  supported_font_format_string = "CID Type 1";  break;
      case FontFormat::CFF:         supported_font_format_string = "CFF";         break;
      case FontFormat::PCF:         supported_font_format_string = "PCF";         break;
      case FontFormat::PFR:         supported_font_format_string = "PFR";         break;
      case FontFormat::TRUETYPE:    supported_font_format_string = "TrueType";    break;
      case FontFormat::TYPE_1:      supported_font_format_string = "Type 1";      break;
      case FontFormat::TYPE_42:     supported_font_format_string = "Type 42";     break;
      case FontFormat::WINDOWS_FNT: supported_font_format_string = "Windows FNT"; break;
      }
    }

    void
    set_library( FT_Library  lib )
    {
      this->library = lib;
    }

    void
    set_raw_bytes( const uint8_t*  data,
                   size_t          size )
    {
      assert( size > 0 );

      (void) files.clear();

#ifdef HAVE_ARCHIVE
      if ( data_is_tar_archive == true )
        (void) tarreader.extract_data( data, size );
      else
#endif
        (void) files.emplace_back( data, data + size );

      num_faces     = -1;
      num_instances = -1;
    }

    void
    set_data_is_tar_archive( bool  is_tar_archive )
    {
      data_is_tar_archive = is_tar_archive;
    }

    void
    set_face_index( FT_Long  index )
    {
      if ( index != face_index )
        num_instances = -1;

      if ( index < 0 || index >= get_num_faces() )
      {
        LOG( ERROR ) << "invalid face index: " << index;
        face_index = 0;
      }
      else
        face_index = index;
    }

    void
    set_instance_index( FT_Long  index )
    {
      if ( index < 0 || index >= get_num_instances() )
      {
        LOG( ERROR ) << "invalid instance index: " << index;
        instance_index = 0;
      }
      else
        instance_index = index;
    }

    FT_Long
    get_num_faces()
    {
      if ( num_faces < 0 )
      {
        Unique_FT_Face  face = load_face();

        if ( face == nullptr )
        {
          LOG( ERROR ) << "load_face failed";
          num_faces = 0;
        }
        else
          num_faces = face->num_faces;
      }
      return num_faces;
    }

    FT_Long
    get_num_instances()
    {
      if ( num_instances < 0 )
      {
        Unique_FT_Face  face = load_face( -1 * ( face_index + 1 ) );

        if ( face == nullptr )
        {
          LOG( ERROR ) << "load_face failed";
          num_instances = 0;
        }
        else
          num_instances = ( face->style_flags >> 16 ) + 1;
      }
      return num_instances;
    }

    Unique_FT_Face
    load()
    {
      return load_face( face_index, instance_index );
    }

  private:

    FT_Library  library = nullptr;

    TarReader  tarreader;

    std::vector<std::vector<FT_Byte>>  files;

    FontFormat   supported_font_format        = FontFormat::NONE;
    std::string  supported_font_format_string = "";

    bool  data_is_tar_archive = false;

    FT_Long  num_faces  = -1;
    FT_Long  face_index =  0;

    FT_Long  num_instances  = -1;
    FT_Long  instance_index =  0;

    Unique_FT_Face
    load_face( FT_Long  face_index     = -1,
               FT_Long  instance_index =  0 )
    {
      FT_Error  error;
      FT_Face   face;

      if ( files.size() < 1 )
      {
        LOG( ERROR ) << "missing data; no data to load a face from";
        return make_unique_face();
      }

      if ( face_index >= 0 )
        face_index += ( instance_index << 16 );

      error = FT_New_Memory_Face( library,
                                  files[0].data(),
                                  files[0].size(),
                                  face_index,
                                  &face );

      LOG_FT_ERROR( "FT_New_Memory_Face", error );

      if ( error != 0 )
        return make_unique_face();

      for ( size_t  i = 1; i < files.size(); i++ )
      {
        FT_Error  err;

        FT_Open_Args  open_args =
        {
          .flags       = FT_OPEN_MEMORY,
          .memory_base = files[i].data(),
          .memory_size = static_cast<FT_Long>( files[i].size() )
        };

        err = FT_Attach_Stream( face, &open_args );
        LOG_FT_ERROR( "FT_Attach_Stream", err );

        if ( err != 0 )
        {
          (void) FT_Done_Face( face );
          return make_unique_face();
        }
      }

      std::string  font_format( FT_Get_Font_Format( face ) );
      if ( font_format != supported_font_format_string )
      {
        LOG( ERROR ) << "invalid font format: "
                     << "received '" << font_format << "' but "
                     << "expected '" << supported_font_format_string << "'";
        (void) FT_Done_Face( face );
        return make_unique_face();
      }

      return make_unique_face( face );
    }
  };

}  // namespace freetype


// ###########################################################################
//
//  SECTION 4 — Visitor / Iterator base classes
//
// ###########################################################################

namespace freetype
{

  // ---- FaceVisitor ---------------------------------------------------------

  class FaceVisitor
    : private noncopyable
  {
  public:

    virtual ~FaceVisitor() = default;

    virtual void
    run( Unique_FT_Face  face ) = 0;

  protected:

    FT_Library  library;
  };

  // ---- GlyphVisitor --------------------------------------------------------

  class GlyphVisitor
    : private noncopyable
  {
  public:

    virtual ~GlyphVisitor() = default;

    virtual void
    run( Unique_FT_Glyph  glyph ) = 0;
  };

  // ---- GlyphRenderIterator -------------------------------------------------

  class GlyphRenderIterator
    : private noncopyable
  {
  public:

    virtual ~GlyphRenderIterator() = default;

    virtual void
    run( Unique_FT_Glyph  glyph ) = 0;

    void
    add_visitor( std::unique_ptr<GlyphVisitor>  visitor )
    {
      (void) glyph_visitors.emplace_back( std::move( visitor ) );
    }

  protected:

    typedef std::vector<std::unique_ptr<GlyphVisitor>>  GlyphVisitors;
    GlyphVisitors  glyph_visitors;
  };

  // ---- GlyphLoadIterator ---------------------------------------------------

  class GlyphLoadIterator
    : private noncopyable
  {
  public:

    GlyphLoadIterator( FT_Long  num_load_glyphs )
    {
      (void) set_num_load_glyphs( num_load_glyphs );
    }

    virtual ~GlyphLoadIterator() = default;

    virtual void
    run( Unique_FT_Face  face ) = 0;

    void
    set_num_load_glyphs( FT_Long  glyphs )
    {
      num_load_glyphs = glyphs;
      LOG( INFO ) << "num glyphs: " << num_load_glyphs;
    }

    void
    add_load_flags( FT_Int32  flags )
    {
      load_flags |= flags;
    }

    void
    add_visitor( std::unique_ptr<GlyphVisitor>  visitor )
    {
      (void) glyph_visitors.emplace_back( std::move( visitor ) );
    }

    void
    add_iterator( std::unique_ptr<GlyphRenderIterator>  iterator )
    {
      (void) glyph_render_iterators.emplace_back( std::move( iterator ) );
    }

  protected:

    FT_Long   num_load_glyphs = -1;
    FT_Int32  load_flags      = FT_LOAD_DEFAULT;

    std::vector<std::unique_ptr<GlyphVisitor>>         glyph_visitors;
    std::vector<std::unique_ptr<GlyphRenderIterator>>  glyph_render_iterators;

    void
    invoke_visitors_and_iterators( const Unique_FT_Glyph&  glyph )
    {
      Unique_FT_Glyph  buffer_glyph = make_unique_glyph();

      for ( auto&  visitor : glyph_visitors )
      {
        buffer_glyph = copy_unique_glyph( glyph );
        if ( buffer_glyph == nullptr )
          return;
        visitor->run( std::move( buffer_glyph ) );
      }

      for ( auto&  iterator : glyph_render_iterators )
      {
        buffer_glyph = copy_unique_glyph( glyph );
        if ( buffer_glyph == nullptr )
          return;
        iterator->run( std::move( buffer_glyph ) );
      }
    }
  };

  // ---- FacePrepIterator ----------------------------------------------------

  class FacePrepIterator
    : private noncopyable
  {
  public:

    virtual ~FacePrepIterator() = default;

    void
    add_visitor( std::unique_ptr<FaceVisitor>  visitor )
    {
      (void) face_visitors.emplace_back( std::move( visitor ) );
    }

    void
    add_iterator( std::unique_ptr<GlyphLoadIterator>  iterator )
    {
      (void) glyph_load_iterators.emplace_back( std::move( iterator ) );
    }

    virtual void
    run( const std::unique_ptr<FaceLoader>&  face_loader ) = 0;

  protected:

    std::vector<std::unique_ptr<FaceVisitor>>        face_visitors;
    std::vector<std::unique_ptr<GlyphLoadIterator>>  glyph_load_iterators;
  };

}  // namespace freetype


// ###########################################################################
//
//  SECTION 5 — Face preparation iterators
//
// ###########################################################################

namespace freetype
{

  // ---- FacePrepIteratorBitmaps ---------------------------------------------

  class FacePrepIteratorBitmaps
    : public FacePrepIterator
  {
  public:

    void
    run( const std::unique_ptr<FaceLoader>&  face_loader ) override
    {
      Unique_FT_Face  face = make_unique_face();
      FT_Int          num_strikes;

      assert( face_loader != nullptr );

      face = face_loader->load();

      if ( face == nullptr )
      {
        LOG( ERROR ) << "face_loader->load() failed";
        return;
      }

      if ( face->style_flags >> 16 != 0 )
        return;

      num_strikes = face->num_fixed_sizes;

      for ( auto  index = 0;
            index < num_strikes &&
              index < STRIKE_INDEX_MAX;
            index++ )
      {
        LOG( INFO )
          << "using bitmap strike "
          << ( index + 1 ) << "/" << num_strikes;

        for ( auto&  visitor : face_visitors )
          visitor->run( get_prepared_face( face_loader, index ) );

        for ( auto&  iterator : glyph_load_iterators )
          iterator->run( get_prepared_face( face_loader, index ) );
      }

      WARN_ABOUT_IGNORED_VALUES( num_strikes,
                                 STRIKE_INDEX_MAX,
                                 "bitmap strikes" );
    }

  private:

    static const FT_Int  STRIKE_INDEX_MAX = 10;

    Unique_FT_Face
    get_prepared_face( const std::unique_ptr<FaceLoader>&  face_loader,
                       FT_Int                              index )
    {
      FT_Error  error;

      Unique_FT_Face  face = face_loader->load();

      if ( face == nullptr )
      {
        LOG( ERROR ) << "face_loader->load() failed";
        return make_unique_face();
      }

      error = FT_Select_Size( face.get(), index );
      LOG_FT_ERROR( "FT_Select_Size", error );

      return error == 0 ? std::move( face ) : make_unique_face();
    }
  };

  // ---- FacePrepIteratorOutlines --------------------------------------------

  class FacePrepIteratorOutlines
    : public FacePrepIterator
  {
  public:

    typedef std::tuple<
      FT_UInt,      // pixel width
      FT_UInt,      // pixel height
      FT_F26Dot6,   // char width
      FT_F26Dot6,   // char height
      FT_UInt,      // horz resolution
      FT_UInt>  CharSizeTuple;

    typedef std::vector<CharSizeTuple>  CharSizeTuples;

    FacePrepIteratorOutlines()
    {
      (void) append_char_size( 16, 16,  8,  8,  72,  72 );
      (void) append_char_size( 16, 32,  8, 20,  72, 300 );
      (void) append_char_size(  0, 32,  0, 20,   0,  72 );
      (void) append_char_size( 32,  0, 64,  0, 300,   0 );
    }

    void
    run( const std::unique_ptr<FaceLoader>&  face_loader ) override
    {
      for ( size_t index = 0; index < char_sizes.size(); index++ )
      {
        LOG( INFO )
          << "using char size "
          << ( index + 1 ) << "/" << char_sizes.size() << ": "
          << std::get<0>( char_sizes[index] ) << " x "
          << std::get<1>( char_sizes[index] ) << " ppem, "
          << ( std::get<2>( char_sizes[index] ) / 64 ) << " x "
          << ( std::get<3>( char_sizes[index] ) / 64 ) << " pt, "
          << std::get<4>( char_sizes[index] ) << " x "
          << std::get<5>( char_sizes[index] ) << " dpi";

        if ( get_prepared_face( face_loader, index ) == nullptr )
          continue;

        for ( auto&  visitor : face_visitors )
          visitor->run( get_prepared_face( face_loader, index ) );

        for ( auto&  iterator : glyph_load_iterators )
          iterator->run( get_prepared_face( face_loader, index ) );
      }
    }

  protected:

    virtual Unique_FT_Face
    get_prepared_face( const std::unique_ptr<FaceLoader>&  face_loader,
                       CharSizeTuples::size_type           index )
    {
      FT_Error  error;

      auto  face = face_loader->load();

      if ( face == nullptr )
      {
        LOG( ERROR ) << "face_loader->load() failed";
        return make_unique_face();
      }

      error = FT_Set_Pixel_Sizes( face.get(),
                                  std::get<0>( char_sizes[index] ),
                                  std::get<1>( char_sizes[index] ) );
      LOG_FT_ERROR( "FT_Set_Pixel_Sizes", error );

      if ( error != 0 )
        return make_unique_face();

      error = FT_Set_Char_Size( face.get(),
                                std::get<2>( char_sizes[index] ),
                                std::get<3>( char_sizes[index] ),
                                std::get<4>( char_sizes[index] ),
                                std::get<5>( char_sizes[index] ) );
      LOG_FT_ERROR( "FT_Set_Char_Size", error );

      return error == 0 ? std::move( face ) : make_unique_face();
    }

  private:

    CharSizeTuples  char_sizes;

    void
    append_char_size( FT_UInt     pixel_width_ppem,
                      FT_UInt     pixel_height_ppem,
                      FT_F26Dot6  char_width_pt,
                      FT_F26Dot6  char_height_pt,
                      FT_UInt     horz_resolution_dpi,
                      FT_UInt     vert_resolution_dpi )
    {
      (void) char_sizes.emplace_back(
        std::make_tuple( pixel_width_ppem,
                         pixel_height_ppem,
                         char_width_pt  * 64,
                         char_height_pt * 64,
                         horz_resolution_dpi,
                         vert_resolution_dpi ) );
    }
  };

  // ---- FacePrepIteratorMultipleMasters --------------------------------------

  class FacePrepIteratorMultipleMasters
    : public FacePrepIteratorOutlines
  {
  protected:

    Unique_FT_Face
    get_prepared_face( const std::unique_ptr<FaceLoader>&  face_loader,
                       CharSizeTuples::size_type           index ) override
    {
      FT_Error  error;

      Unique_FT_Face  face =
        FacePrepIteratorOutlines::get_prepared_face( face_loader, index );

      FT_Library             library;
      FT_MM_Var*             master = nullptr;
      std::vector<FT_Fixed>  coords;

      if ( face == nullptr )
        return make_unique_face();

      if ( FT_HAS_MULTIPLE_MASTERS( face ) == 0 )
        return make_unique_face();

      library = face->glyph->library;

      error = FT_Get_MM_Var( face.get(), &master );
      LOG_FT_ERROR( "FT_Get_MM_Var", error );

      if ( error != 0 )
        return free_and_return( library, master, make_unique_face() );

      for ( auto  i = 0u;
            i < master->num_axis &&
              i < AXIS_INDEX_MAX;
            i++ )
        coords.push_back( ( master->axis[i].minimum +
                            master->axis[i].def ) / 2 );

      WARN_ABOUT_IGNORED_VALUES( master->num_axis, AXIS_INDEX_MAX, "axis" );

      error = FT_Set_Var_Design_Coordinates( face.get(),
                                             coords.size(),
                                             coords.data() );
      LOG_FT_ERROR( "FT_Set_Var_Design_Coordinates", error );

      if ( error != 0 )
        return free_and_return( library, master, make_unique_face() );

      return free_and_return( library, master, std::move( face ) );
    }

  private:

    static const FT_UInt  AXIS_INDEX_MAX = 10;

    Unique_FT_Face
    free_and_return( FT_Library      library,
                     FT_MM_Var*      master,
                     Unique_FT_Face  face )
    {
      (void) FT_Done_MM_Var( library, master );
      return face;
    }
  };

}  // namespace freetype


// ###########################################################################
//
//  SECTION 6 — FaceLoadIterator
//
// ###########################################################################

namespace freetype
{

  class FaceLoadIterator
    : private noncopyable
  {
  public:

    FaceLoadIterator()
      : face_loader( new FaceLoader ) {}

    ~FaceLoadIterator() {}

    void
    set_supported_font_format( FaceLoader::FontFormat  format )
    {
      assert( face_loader != nullptr );
      (void) face_loader->set_supported_font_format( format );
    }

    void
    set_library( FT_Library  library )
    {
      assert( face_loader != nullptr );
      (void) face_loader->set_library( library );
    }

    void
    set_raw_bytes( const uint8_t*  data,
                   size_t          size )
    {
      assert( face_loader != nullptr );
      (void) face_loader->set_raw_bytes( data, size );
    }

    void
    set_data_is_tar_archive( bool  is_tar_archive )
    {
      assert( face_loader != nullptr );
      (void) face_loader->set_data_is_tar_archive( is_tar_archive );
    }

    void
    add_once_visitor( std::unique_ptr<FaceVisitor>  visitor )
    {
      (void) once_face_visitors.emplace_back( std::move( visitor ) );
    }

    void
    add_always_visitor( std::unique_ptr<FaceVisitor>  visitor )
    {
      (void) always_face_visitors.emplace_back( std::move( visitor ) );
    }

    void
    add_iterator( std::unique_ptr<FacePrepIterator>  iterator )
    {
      (void) face_prep_iterators.emplace_back( std::move( iterator ) );
    }

    void
    run()
    {
      Unique_FT_Face  face = make_unique_face();

      const char*  face_name;

      FT_Long  num_faces;
      FT_Long  num_instances;

      assert( face_loader != nullptr );

      num_faces = face_loader->get_num_faces();

      for ( auto  face_index = 0;
            face_index < num_faces &&
              face_index < FACE_INDEX_MAX;
            face_index++ )
      {
        (void) face_loader->set_face_index( face_index );

        if ( face_loader->load() == nullptr )
        {
          LOG( ERROR ) << "face_loader->load failed";
          continue;
        }

        if ( face_index == 0 )
        {
          LOG( INFO ) << "fs type flags: 0x" << std::hex
                      << FT_Get_FSType_Flags( face.get() );

          for ( auto&  visitor : once_face_visitors )
            visitor->run( face_loader->load() );
        }

        num_instances = face_loader->get_num_instances();

        for ( auto  instance_index = 0;
              instance_index < num_instances &&
                instance_index < INSTANCE_INDEX_MAX;
              instance_index++ )
        {
          face_loader->set_instance_index( instance_index );

          LOG( INFO ) << "using face "
                      << ( face_index + 1 ) << "/" << num_faces << ", "
                      << "instance "
                      << ( instance_index + 1 ) << "/" << num_instances;

          face = face_loader->load();

          if ( face == nullptr )
          {
            LOG( ERROR ) << "face_loader->load failed";
            continue;
          }

          face_name = FT_Get_Postscript_Name( face.get() );
          LOG_IF( INFO, face_name != nullptr )
            << "postscript name: " << face_name;

          for ( auto&  visitor : always_face_visitors )
            visitor->run( face_loader->load() );

          for ( auto&  iterator : face_prep_iterators )
            iterator->run( face_loader );
        }

        WARN_ABOUT_IGNORED_VALUES( num_instances,
                                   INSTANCE_INDEX_MAX,
                                   "instances" );
      }

      WARN_ABOUT_IGNORED_VALUES( num_faces, FACE_INDEX_MAX, "faces" );
    }

  private:

    static const FT_Long  FACE_INDEX_MAX     = 5;
    static const FT_Long  INSTANCE_INDEX_MAX = 5;

    std::unique_ptr<FaceLoader>  face_loader;

    std::vector<std::unique_ptr<FaceVisitor>>  once_face_visitors;
    std::vector<std::unique_ptr<FaceVisitor>>  always_face_visitors;

    std::vector<std::unique_ptr<FacePrepIterator>>  face_prep_iterators;
  };

}  // namespace freetype


// ###########################################################################
//
//  SECTION 7 — Face visitors
//
// ###########################################################################

namespace freetype
{

  // ---- FaceVisitorAutohinter -----------------------------------------------

  class FaceVisitorAutohinter
    : public FaceVisitor
  {
  public:

    void
    run( Unique_FT_Face  face ) override
    {
      assert( face != nullptr );

      for ( auto  warping : warpings )
      {
        LOG( INFO ) << ( warping == 1 ? "" : "not " ) << "using warping";

        (void) set_property( face, "warping", &warping );
        (void) load_glyphs( face );
      }

      (void) set_property( face, "warping", &default_warping );
    }

  private:

    static const FT_Long   GLYPH_INDEX_MAX = 30;
    static const FT_Int32  LOAD_FLAGS      = FT_LOAD_FORCE_AUTOHINT |
                                             FT_LOAD_NO_BITMAP;

    FT_Bool               default_warping = 0;
    std::vector<FT_Bool>  warpings{ 0, 1 };

    void
    set_property( Unique_FT_Face&    face,
                  const std::string  property_name,
                  const void*        value )
    {
      (void) FT_Property_Set( face->glyph->library,
                              "autofitter",
                              property_name.c_str(),
                              value );
    }

    void
    load_glyphs( Unique_FT_Face&  face )
    {
      FT_Error  error;
      FT_Long   num_glyphs = face->num_glyphs;

      for ( auto  index = 0;
            index < num_glyphs &&
              index < GLYPH_INDEX_MAX;
            index++ )
      {
        LOG( INFO ) << "testing glyph " << ( index + 1 ) << "/" << num_glyphs;

        error = FT_Load_Glyph( face.get(), index, LOAD_FLAGS );
        LOG_FT_ERROR( "FT_Load_Glyph", error );
      }

      WARN_ABOUT_IGNORED_VALUES( num_glyphs, GLYPH_INDEX_MAX, "glyphs" );
    }
  };

  // ---- FaceVisitorLoadGlyphs -----------------------------------------------

  class FaceVisitorLoadGlyphs
    : public FaceVisitor
  {
  public:

    FaceVisitorLoadGlyphs( FT_Long  num_used_glyphs )
    {
      (void) set_num_used_glyphs( num_used_glyphs );
      (void) add_transformation( nullptr, nullptr );
    }

    void
    run( Unique_FT_Face  face ) override
    {
      FT_Error  error;
      FT_Long   num_glyphs;

      assert( face            != nullptr &&
              num_used_glyphs >  0 );

      num_glyphs = face->num_glyphs;

      for ( auto  transformation : transformations )
      {
        FT_Matrix*  matrix = transformation.first;
        FT_Vector*  vector = transformation.second;

        LOG_IF( INFO, matrix == nullptr )
          << "setting transformation matrix: none";
        LOG_IF( INFO, matrix != nullptr )
          << "setting transformation matrix: "
          << matrix->xx << ", " << matrix->xy << "; "
          << matrix->yx << ", " << matrix->yy;

        LOG_IF( INFO, vector == nullptr ) << "setting transform vector: none";
        LOG_IF( INFO, vector != nullptr )
          << "setting transform vector: "
          << vector->x << ", " << vector->y;

        (void) FT_Set_Transform( face.get(), matrix, vector );

        for ( auto  index = 0;
              index < num_glyphs &&
                index < num_used_glyphs;
              index++ )
        {
          LOG( INFO ) << "testing glyph "
                      << ( index + 1 ) << "/" << num_glyphs;

          for ( auto  flags : load_flags )
          {
            LOG( INFO ) << "load flags: 0x" << std::hex << flags;

            error = FT_Load_Glyph( face.get(), index, flags );
            LOG_FT_ERROR( "FT_Load_Glyph", error );
          }
        }

        WARN_ABOUT_IGNORED_VALUES( num_glyphs, num_used_glyphs, "glyphs" );
      }
    }

  protected:

    void
    set_num_used_glyphs( FT_Long  glyphs )
    {
      assert( glyphs > 0 );
      num_used_glyphs = glyphs;
    }

    void
    add_transformation( FT_Matrix*  matrix,
                        FT_Vector*  delta )
    {
      (void) transformations.push_back( { matrix, delta } );
    }

    void
    add_load_flags( FT_Int32  flags )
    {
      (void) this->load_flags.push_back( flags );
    }

  private:

    typedef std::vector<std::pair<FT_Matrix*, FT_Vector*>>  Transformations;

    FT_Long  num_used_glyphs = -1;

    Transformations        transformations;
    std::vector<FT_Int32>  load_flags;
  };

  // ---- FaceVisitorLoadGlyphsBitmaps ----------------------------------------

  class FaceVisitorLoadGlyphsBitmaps
    : public FaceVisitorLoadGlyphs
  {
  public:

    FaceVisitorLoadGlyphsBitmaps()
      : FaceVisitorLoadGlyphs( NUM_USED_GLYPHS )
    {
      (void) add_load_flags( FT_LOAD_DEFAULT             );
      (void) add_load_flags( FT_LOAD_VERTICAL_LAYOUT     );
      (void) add_load_flags( FT_LOAD_LINEAR_DESIGN       );
      (void) add_load_flags( FT_LOAD_COLOR               );
      (void) add_load_flags( FT_LOAD_BITMAP_METRICS_ONLY );
    }

  private:

    static const FT_Long  NUM_USED_GLYPHS = 30;
  };

  // ---- FaceVisitorLoadGlyphsOutlines ----------------------------------------

  class FaceVisitorLoadGlyphsOutlines
    : public FaceVisitorLoadGlyphs
  {
  public:

    FaceVisitorLoadGlyphsOutlines()
      : FaceVisitorLoadGlyphs( NUM_USED_GLYPHS )
    {
      FT_Int32  flags = FT_LOAD_NO_BITMAP | FT_LOAD_NO_AUTOHINT;

      // Rotate by 3 degrees.
      matrix.xx = 0x10000L *  0.99862;
      matrix.xy = 0x10000L * -0.05233;
      matrix.yx = 0x10000L *  0.05233;
      matrix.yy = 0x10000L *  0.99862;

      // Coordinates are expressed in 1/64th of a pixel.
      delta.x = -3 * 64;
      delta.y =  3 * 64;

      (void) add_transformation( nullptr, &delta  );
      (void) add_transformation( &matrix, nullptr );
      (void) add_transformation( &matrix, &delta  );

      (void) add_load_flags( flags                           );
      (void) add_load_flags( flags | FT_LOAD_NO_SCALE        );
      (void) add_load_flags( flags | FT_LOAD_NO_HINTING      );
      (void) add_load_flags( flags | FT_LOAD_VERTICAL_LAYOUT );
      (void) add_load_flags( flags | FT_LOAD_PEDANTIC        );
      (void) add_load_flags( flags | FT_LOAD_LINEAR_DESIGN   );
      (void) add_load_flags( flags | FT_LOAD_COMPUTE_METRICS );
    }

  private:

    static const FT_Long  NUM_USED_GLYPHS = 5;

    FT_Matrix  matrix;
    FT_Vector  delta;
  };

  // ---- FaceVisitorRenderGlyphs ---------------------------------------------

  class FaceVisitorRenderGlyphs
    : public FaceVisitor
  {
  public:

    void
    run( Unique_FT_Face  face ) override
    {
      FT_Error  error;
      FT_Long   num_glyphs;

      assert( face != nullptr );

      num_glyphs = face->num_glyphs;

      for ( auto  index = 0;
            index < num_glyphs &&
              index < GLYPH_INDEX_MAX;
            index++ )
      {
        LOG( INFO ) << "testing glyph "
                    << ( index + 1 ) << "/" << num_glyphs;

        for ( auto  mode : RENDER_MODES )
        {
          LOG( INFO ) << "load flags: 0x" << std::hex << mode.first;

          error = FT_Load_Glyph( face.get(), index, mode.first );
          LOG_FT_ERROR( "FT_Load_Glyph", error );

          if ( error != 0 )
            continue;

          if ( glyph_has_reasonable_render_size(
                 get_unique_glyph_from_face( face ) ) == false )
            continue;

          LOG( INFO ) << "render mode: " << mode.second;

          error = FT_Render_Glyph( face->glyph, mode.second );
          LOG_FT_ERROR( "FT_Render_Glyph", error );
        }
      }

      WARN_ABOUT_IGNORED_VALUES( num_glyphs, GLYPH_INDEX_MAX, "glyphs" );
    }

  private:

    typedef std::vector<std::pair<FT_Int32, FT_Render_Mode>>  RenderModes;

    static const FT_Long      GLYPH_INDEX_MAX = 5;

    const RenderModes  RENDER_MODES =
    {
      { FT_LOAD_NO_BITMAP | FT_LOAD_TARGET_NORMAL, FT_RENDER_MODE_NORMAL },
      { FT_LOAD_NO_BITMAP | FT_LOAD_TARGET_LIGHT,  FT_RENDER_MODE_LIGHT  },
      { FT_LOAD_NO_BITMAP | FT_LOAD_TARGET_MONO,   FT_RENDER_MODE_MONO   },
      { FT_LOAD_NO_BITMAP | FT_LOAD_TARGET_LCD,    FT_RENDER_MODE_LCD    },
      { FT_LOAD_NO_BITMAP | FT_LOAD_TARGET_LCD_V,  FT_RENDER_MODE_LCD_V  }
    };
  };

  // ---- FaceVisitorSubGlyphs ------------------------------------------------

  class FaceVisitorSubGlyphs
    : public FaceVisitor
  {
  public:

    void
    run( Unique_FT_Face  face ) override
    {
      FT_Error  error;

      FT_Long  num_glyphs;
      FT_UInt  num_subglyphs;

      FT_Int     sg_index;
      FT_UInt    sg_flags;
      FT_Int     sg_arg1;
      FT_Int     sg_arg2;
      FT_Matrix  sg_transform;

      assert( face != nullptr );

      num_glyphs = face->num_glyphs;

      for ( auto  index = 0;
            index < num_glyphs &&
              index < GLYPH_INDEX_MAX;
            index++ )
      {
        LOG( INFO ) << "testing glyph "
                    << ( index + 1 ) << "/" << num_glyphs;

        error = FT_Load_Glyph( face.get(), index, LOAD_FLAGS );
        LOG_FT_ERROR( "FT_Load_Glyph", error );

        if ( error != 0 )
          continue;

        if ( face->glyph->format != FT_GLYPH_FORMAT_COMPOSITE )
        {
          LOG( INFO ) << "no composite glyph found";
          continue;
        }

        num_subglyphs = face->glyph->num_subglyphs;

        for ( FT_UInt sub_index = 0;
              sub_index < num_subglyphs &&
                sub_index < SUBGLYPH_INDEX_MAX;
              sub_index++ )
        {
          error = FT_Get_SubGlyph_Info( face->glyph,
                                        sub_index,
                                        &sg_index,
                                        &sg_flags,
                                        &sg_arg1,
                                        &sg_arg2,
                                        &sg_transform );
          LOG_FT_ERROR( "FT_Get_SubGlyph_Info", error );

          LOG_IF( INFO, error == 0 )
            << "subglyph " << ( sub_index + 1 ) << "/" << num_subglyphs
            << ": "
            << "glyph #" << sg_index << ", "
            << "flags 0x" << std::hex << sg_flags;
        }

        WARN_ABOUT_IGNORED_VALUES( num_subglyphs,
                                   SUBGLYPH_INDEX_MAX,
                                   "subglyphs" );
      }

      WARN_ABOUT_IGNORED_VALUES( num_glyphs, GLYPH_INDEX_MAX, "glyphs" );
    }

  private:

    static const FT_Long   GLYPH_INDEX_MAX    = 30;
    static const FT_Long   SUBGLYPH_INDEX_MAX = 10;
    static const FT_Int32  LOAD_FLAGS         = FT_LOAD_NO_BITMAP |
                                                FT_LOAD_NO_RECURSE;
  };

}  // namespace freetype


// ###########################################################################
//
//  SECTION 8 — FuzzTarget → FaceFuzzTarget → TrueTypeRenderFuzzTarget
//
// ###########################################################################

namespace freetype
{

  // ---- FuzzTarget (abstract base) ------------------------------------------

  class FuzzTarget
    : private noncopyable
  {
  public:

    virtual ~FuzzTarget()
    {
      (void) FT_Done_FreeType( library );
      library = nullptr;
    }

    virtual void
    run( const uint8_t*  data,
         size_t          size ) = 0;

  protected:

    FuzzTarget()
    {
      FT_Error  error;

      FT_Int  major;
      FT_Int  minor;
      FT_Int  patch;

      error = FT_Init_FreeType( &library );
      LOG_FT_ERROR( "FT_Init_FreeType", error );

      if ( error != 0 )
        return;

      (void) FT_Library_Version( library, &major, &minor, &patch );
      LOG( INFO ) << "Using FreeType "
                  << major << "." << minor << "." << patch;
    }

    FT_Library
    get_ft_library()
    {
      return library;
    }

#ifdef FT2_BUILD_LIBRARY
    FT_Memory
    get_ft_memory()
    {
      return library->memory;
    }
#endif

  private:

    FT_Library  library = nullptr;
  };

  // ---- FaceFuzzTarget ------------------------------------------------------

  class FaceFuzzTarget
    : public FuzzTarget
  {
  public:

    void
    run( const uint8_t*  data,
         size_t          size ) override
    {
      if ( size < 1 )
        return;

      assert( face_load_iterator != nullptr );

      (void) face_load_iterator->set_library( get_ft_library() );
      (void) face_load_iterator->set_raw_bytes( data, size );
      (void) face_load_iterator->run();
    }

  protected:

    FaceFuzzTarget() = default;

    static const FT_UInt  HINTING_ADOBE;
    static const FT_UInt  HINTING_FREETYPE;

    void
    set_supported_font_format( FaceLoader::FontFormat  format )
    {
      assert( face_load_iterator != nullptr );
      (void) face_load_iterator->set_supported_font_format( format );
    }

    void
    set_data_is_tar_archive( bool  is_tar_archive )
    {
      assert( face_load_iterator != nullptr );
      (void) face_load_iterator->set_data_is_tar_archive( is_tar_archive );
    }

    bool
    set_property( const std::string  module_name,
                  const std::string  property_name,
                  const void*        value )
    {
      FT_Error  error;

      LOG( INFO ) << "setting '" << property_name
                  << "' in '"   << module_name << "'";

      error = FT_Property_Set( get_ft_library(),
                               module_name.c_str(),
                               property_name.c_str(),
                               value );

      LOG_FT_ERROR( "FT_Property_Set", error );

      return error == 0 ? true : false;
    }

    std::unique_ptr<FaceLoadIterator>&
    set_iterator( std::unique_ptr<FaceLoadIterator>  iterator )
    {
      face_load_iterator = std::move( iterator );
      return face_load_iterator;
    }

  private:

    std::unique_ptr<FaceLoadIterator>  face_load_iterator;
  };

  const FT_UInt  FaceFuzzTarget::HINTING_ADOBE    = FT_HINTING_ADOBE;
  const FT_UInt  FaceFuzzTarget::HINTING_FREETYPE = FT_HINTING_FREETYPE;

  // ---- TrueTypeRenderFuzzTarget --------------------------------------------

  class TrueTypeRenderFuzzTarget
    : public FaceFuzzTarget
  {
  public:

    TrueTypeRenderFuzzTarget()
    {
      auto  fli = freetype::make_unique<FaceLoadIterator>();

      auto  fpi_bitmaps  = freetype::make_unique<FacePrepIteratorBitmaps>();
      auto  fpi_outlines = freetype::make_unique<FacePrepIteratorOutlines>();
      auto  fpi_mm =
        freetype::make_unique<FacePrepIteratorMultipleMasters>();

      // -------------------------------------------------------------------
      // Face preparation iterators:

      (void) fpi_bitmaps
        ->add_visitor(
            freetype::make_unique<FaceVisitorLoadGlyphsBitmaps>() );

      (void) fpi_outlines
        ->add_visitor( freetype::make_unique<FaceVisitorAutohinter>() );
      (void) fpi_outlines
        ->add_visitor(
            freetype::make_unique<FaceVisitorLoadGlyphsOutlines>() );
      (void) fpi_outlines
        ->add_visitor( freetype::make_unique<FaceVisitorRenderGlyphs>() );
      (void) fpi_outlines
        ->add_visitor( freetype::make_unique<FaceVisitorSubGlyphs>() );

      (void) fpi_mm
        ->add_visitor( freetype::make_unique<FaceVisitorAutohinter>() );
      (void) fpi_mm
        ->add_visitor(
            freetype::make_unique<FaceVisitorLoadGlyphsOutlines>() );
      (void) fpi_mm
        ->add_visitor( freetype::make_unique<FaceVisitorRenderGlyphs>() );
      (void) fpi_mm
        ->add_visitor( freetype::make_unique<FaceVisitorSubGlyphs>() );

      // -------------------------------------------------------------------
      // Face load iterators:

      (void) fli->set_supported_font_format(
                     FaceLoader::FontFormat::TRUETYPE );

      (void) fli->add_iterator( std::move( fpi_bitmaps  ) );
      (void) fli->add_iterator( std::move( fpi_outlines ) );
      (void) fli->add_iterator( std::move( fpi_mm       ) );

      // -------------------------------------------------------------------
      // Fuzz target:

      (void) set_property( "truetype",
                           "interpreter-version",
                           &INTERPRETER_VERSION_40 );

      (void) set_iterator( std::move( fli ) );
    }

  protected:

    static const FT_UInt  INTERPRETER_VERSION_35;
    static const FT_UInt  INTERPRETER_VERSION_38;
    static const FT_UInt  INTERPRETER_VERSION_40;
  };

  const FT_UInt  TrueTypeRenderFuzzTarget::INTERPRETER_VERSION_35 =
    TT_INTERPRETER_VERSION_35;
  const FT_UInt  TrueTypeRenderFuzzTarget::INTERPRETER_VERSION_38 =
    TT_INTERPRETER_VERSION_38;
  const FT_UInt  TrueTypeRenderFuzzTarget::INTERPRETER_VERSION_40 =
    TT_INTERPRETER_VERSION_40;

}  // namespace freetype


// ###########################################################################
//
//  SECTION 9 — LLVMFuzzerTestOneInput entry point
//
// ###########################################################################

namespace {

  freetype::TrueTypeRenderFuzzTarget  target;

  extern "C" int
  LLVMFuzzerTestOneInput( const uint8_t*  data,
                          size_t          size )
  {
    (void) target.run( data, size );
    return 0;
  }

}
