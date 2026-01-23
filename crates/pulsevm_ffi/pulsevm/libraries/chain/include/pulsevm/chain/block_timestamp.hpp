#pragma once
#include "config.hpp"

#include <stdint.h>
#include <fc/time.hpp>
#include <fc/variant.hpp>
#include <fc/string.hpp>
#include <fc/exception/exception.hpp>
#include <limits>

namespace pulsevm { namespace chain {

   /**
   * This class is used in the block headers to represent the block time
   * It is a parameterised class that takes an Epoch in milliseconds and
   * and an interval in milliseconds and computes the number of slots.
   **/
   template<uint16_t IntervalMs, uint64_t EpochMs>
   class block_timestamp {
      public:

         block_timestamp() : slot(0) {}

         explicit block_timestamp( uint32_t s ) :slot(s){}

         block_timestamp(const fc::time_point& t) {
            set_time_point(t);
         }

         block_timestamp(const fc::time_point_sec& t) {
            set_time_point(t);
         }

         static block_timestamp maximum() { return block_timestamp( 0xffff ); }
         static block_timestamp min() { return block_timestamp(0); }

         std::shared_ptr<fc::time_point> to_time_point() const {
            return std::make_shared<fc::time_point>((fc::time_point)(*this));
         }

         uint32_t get_slot() const {
            return slot;
         }

         operator fc::time_point() const {
            int64_t msec = slot * (int64_t)IntervalMs;
            msec += EpochMs;
            return fc::time_point(fc::milliseconds(msec));
         }

         void operator = (const fc::time_point& t ) {
            set_time_point(t);
         }

         // needed, otherwise deleted because of above version of operator=()
         block_timestamp& operator=(const block_timestamp&) = default;

         auto operator<=>(const block_timestamp&) const = default;

         uint32_t slot;

      private:
      void set_time_point(const fc::time_point& t) {
         auto micro_since_epoch = t.time_since_epoch();
         auto msec_since_epoch  = micro_since_epoch.count() / 1000;
         slot = ( msec_since_epoch - EpochMs ) / IntervalMs;
      }

      void set_time_point(const fc::time_point_sec& t) {
         uint64_t  sec_since_epoch = t.sec_since_epoch();
         slot = (sec_since_epoch * 1000 - EpochMs) / IntervalMs;
      }
   }; // block_timestamp

   typedef block_timestamp<config::block_interval_ms,config::block_timestamp_epoch> block_timestamp_type; 

} } /// pulsevm::chain

namespace std {
   inline std::ostream& operator<<(std::ostream& os, const pulsevm::chain::block_timestamp_type& t) {
      os << "tstamp(" << t.slot << ")";
      return os;
   }
}


#include <fc/reflect/reflect.hpp>
FC_REFLECT(pulsevm::chain::block_timestamp_type, (slot))

namespace fc {
  template<uint16_t IntervalMs, uint64_t EpochMs>
  void to_variant(const pulsevm::chain::block_timestamp<IntervalMs,EpochMs>& t, fc::variant& v) {
     to_variant( (fc::time_point)t, v);
  }

  template<uint16_t IntervalMs, uint64_t EpochMs>
  void from_variant(const fc::variant& v, pulsevm::chain::block_timestamp<IntervalMs,EpochMs>& t) {
     t = v.as<fc::time_point>();
  }
}

#ifdef _MSC_VER
  #pragma warning (pop)
#endif /// #ifdef _MSC_VER
